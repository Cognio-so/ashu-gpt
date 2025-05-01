from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from fastapi.middleware.cors import CORSMiddleware
import os
from KB_indexer import KB_indexer
from dotenv import load_dotenv
import shutil
import tempfile
import uuid
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from fastapi import WebSocket
import time
from werkzeug.utils import secure_filename
from fastapi.concurrency import run_in_threadpool
from multiprocessing import cpu_count
import boto3
from botocore.client import Config
import magic
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://agt-tester-frontend.vercel.app","http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory - add this after app = FastAPI()
os.makedirs(os.path.join(os.getcwd(), "public", "uploads"), exist_ok=True)
app.mount("/public", StaticFiles(directory="public"), name="public")

# Store models in a global dictionary for reuse
# Add this after the app definition (around line 25)
gpt_model_cache = {}  # Maps collection_name to model

# Store API keys for different models
MODEL_API_KEYS = {
    "gpt-4": os.environ.get("OPENAI_API_KEY"),
    "gpt-4o-mini": os.environ.get("OPENAI_API_KEY"),
    "gpt-3.5": os.environ.get("OPENAI_API_KEY"),
    "claude": os.environ.get("ANTHROPIC_API_KEY"),
    "gemini": os.environ.get("GOOGLE_API_KEY"),
    "llama": os.environ.get("META_API_KEY")
}

# Add a model translation dictionary near the top of main.py
MODEL_TRANSLATIONS = {
    "gpt-4": "gpt-4o",          # Latest GPT-4 model
    "gpt-4o-mini": "gpt-4o-mini", # Latest GPT-4 model
    "gpt-3.5": "gpt-3.5-turbo", # Correct model name for API
    "claude": "claude-3-opus-20240229",  # Latest Claude model
    "gemini": "gemini-pro",     # Google's Gemini model
    "llama": "llama-3-70b-chat" # Meta's Llama model
}

# R2 Configuration
R2_ENDPOINT = os.environ.get("R2_ENDPOINT")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")
R2_PUBLIC_URL = os.environ.get("R2_PUBLIC_URL")  # e.g., https://your-bucket.your-account.r2.cloudflarestorage.com

def get_r2_client():
    """Create and return a boto3 client for Cloudflare R2"""
    return boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version='s3v4')
    )

class IndexRequest(BaseModel):
    file_urls: List[str]
    user_email: str
    gpt_name: str
    gpt_id: str
    force_recreate: bool = False
    use_hybrid_search: bool = False  # Add hybrid search parameter
    system_prompt: Optional[str] = None  # Add system prompt field
    schema: Optional[Dict] = None  # Add schema field for all GPT configuration

class GPTOpenRequest(BaseModel):
    """Model for handling when a custom GPT opens"""
    user_email: str
    gpt_name: str
    gpt_id: str
    file_urls: List[str]
    schema: Optional[Dict] = None  # The GPT's schema/configuration
    use_hybrid_search: bool = False  # Add hybrid search parameter

# Add new chat model
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    collection_name: str
    history: Optional[List[Message]] = []
    memory: Optional[List[Dict[str, Any]]] = []  # Add memory field
    user_documents: Optional[List[str]] = []
    use_hybrid_search: bool = False  # Add hybrid search parameter

@app.get("/")
async def root():
    """Root endpoint for health checks"""
    return {
        "status": "online",
        "message": "AI Agent backend is running",
        "version": "1.0.0"
    }

@app.post("/gpt-opened")
async def gpt_opened(request: GPTOpenRequest):
    """
    Endpoint triggered when a custom GPT opens.
    Automatically indexes the knowledge specified in the GPT's schema.
    """
    try:
        # Sanitize inputs for collection name
        sanitized_email = ''.join(c if c.isalnum() else '_' for c in request.user_email)
        sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in request.gpt_name)
        
        # Ensure collection name starts with a letter
        collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
        collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}_{request.gpt_id}"
        collection_name = collection_name[:63]  # Limit length
        
        # Extract and store model from schema with better logging
        frontend_model = "gpt-4o-mini"  # Default model
        use_hybrid_search = request.use_hybrid_search  # Default from request
        system_prompt = None  # Initialize system prompt variable
        
        if request.schema:
            # Extract model from schema
            if 'model' in request.schema:
                frontend_model = request.schema['model']
                
                # Translate to actual API model name
                model = MODEL_TRANSLATIONS.get(frontend_model, frontend_model)
                
                print(f"✅ CustomGPT using model: {frontend_model} (API: {model}) for collection: {collection_name}")
                
            # Extract system prompt from schema
            if 'instructions' in request.schema:
                system_prompt = request.schema['instructions']
                print(f"✅ Extracted system prompt from schema: {system_prompt[:50]}...")
            
            # Store the complete schema and system prompt in the model cache
            gpt_model_cache[collection_name] = {
                'model': frontend_model,
                'schema': request.schema,
                'system_prompt': system_prompt
            }
            
            # Check if hybrid search is requested in schema
            if 'use_hybrid_search' in request.schema:
                use_hybrid_search = request.schema['use_hybrid_search']
        
        print(f"📊 Using hybrid search: {use_hybrid_search}")
        
        # Get configuration from environment
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        openai_api_key = os.environ.get("OPENAI_API_KEY")
        
        # We don't force recreate by default when a GPT opens to avoid losing indexed data
        force_recreate = False
        
        # Run indexer with files from GPT schema
        success = KB_indexer(
            file_urls=request.file_urls,
            qdrant_url=qdrant_url,
            qdrant_api_key=qdrant_api_key,
            collection_name=collection_name,
            openai_api_key=openai_api_key,
            force_recreate_collection=force_recreate,
            max_workers=5,
            use_hybrid_search=use_hybrid_search,
            system_prompt=system_prompt,  # Pass system prompt to KB_indexer
            schema=request.schema  # Pass full schema to KB_indexer
        )
        
        if success:
            return {
                "success": True, 
                "collection_name": collection_name,
                "message": "GPT knowledge base indexed successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="KB indexing failed when GPT opened")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during GPT initialization: {str(e)}")

@app.post("/index-knowledge")
async def index_knowledge(request: IndexRequest):
    # Sanitize inputs for collection name
    sanitized_email = ''.join(c if c.isalnum() else '_' for c in request.user_email)
    sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in request.gpt_name)
    
    # Ensure collection name starts with a letter
    collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
    collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}_{request.gpt_id}"
    collection_name = collection_name[:63]  # Limit length
    
    # Get configuration from environment
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_api_key = os.environ.get("QDRANT_API_KEY")
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    
    # Store the system prompt and schema in the model cache if provided
    if request.system_prompt:
        # If schema exists, add or update system_prompt
        schema = request.schema or {}
        schema['instructions'] = request.system_prompt
        gpt_model_cache[collection_name] = {
            'model': schema.get('model', 'gpt-4o-mini'),
            'schema': schema
        }
        print(f"✅ Stored system prompt for collection: {collection_name}")
    
    # Store the full schema if provided
    elif request.schema:
        model = request.schema.get('model', 'gpt-4o-mini')
        gpt_model_cache[collection_name] = {
            'model': model,
            'schema': request.schema
        }
        print(f"✅ Stored schema for collection: {collection_name}")
    
    # Run indexer
    success = KB_indexer(
        file_urls=request.file_urls,
        qdrant_url=qdrant_url,
        qdrant_api_key=qdrant_api_key,
        collection_name=collection_name,
        openai_api_key=openai_api_key,
        force_recreate_collection=request.force_recreate,
        max_workers=5,
        use_hybrid_search=request.use_hybrid_search,
        system_prompt=request.system_prompt,  # Pass system prompt to KB_indexer
        schema=request.schema  # Pass full schema to KB_indexer
    )
    
    if success:
        return {"success": True, "collection_name": collection_name}
    else:
        raise HTTPException(status_code=500, detail="KB indexing failed")

@app.post("/chat")
async def chat(request: ChatRequest):
    """Handle chat requests with RAG support using both knowledge base and user documents"""
    try:
        # Extract params from request
        message = request.message
        collection_name = request.collection_name
        user_documents = request.user_documents or []
        history = request.history or []
        memory = request.memory or []  # Add memory extraction
        
        # Define user documents collection if present
        user_collection_name = f"{collection_name}_user_docs" if user_documents else None
        
        # Get the model and system prompt from cache
        cached_data = gpt_model_cache.get(collection_name, {})
        if isinstance(cached_data, str):
            # Handle legacy format where only model name was stored
            frontend_model = cached_data
            system_prompt = None
        else:
            # Handle new format with full schema
            frontend_model = cached_data.get('model', "gpt-4o-mini")
            
            # Extract system prompt from schema if available
            if 'schema' in cached_data and 'instructions' in cached_data['schema']:
                system_prompt = cached_data['schema']['instructions']
            elif 'system_prompt' in cached_data:
                system_prompt = cached_data['system_prompt']
            else:
                system_prompt = None
        
        # Append markdown enhancement to user-provided system prompt
        if system_prompt:
            if not "markdown" in system_prompt.lower():
                system_prompt += "\n\nAlways format your responses in proper markdown with appropriate headings, bullet points, tables, and emojis where relevant."
        
        # Enhance the system prompt with stronger guardrails against hallucination
        if system_prompt:
            # Add anti-hallucination guardrails if not already present
            if not "hallucinate" in system_prompt.lower():
                system_prompt = f"""
{system_prompt}

IMPORTANT GUIDELINES:
1. NEVER make up information that isn't in the provided context
2. If you don't have enough information to answer, clearly state what specific information is missing
3. Only reference documents and information that actually exist in the provided context
4. Format your response with proper markdown for readability
"""
        
        # Translate frontend model name to actual API model name
        model = MODEL_TRANSLATIONS.get(frontend_model, frontend_model)
        
        print(f"🤖 Using model {frontend_model} (API: {model}) for chat with collection {collection_name}")
        if system_prompt:
            print(f"📝 Using custom system prompt: {system_prompt[:50]}...")
        
        # Get configuration from environment
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        openai_api_key = os.environ.get("OPENAI_API_KEY")
        
        # Get the appropriate API key based on model
        if frontend_model.startswith("gpt-"):
            openai_api_key = MODEL_API_KEYS.get("gpt-4", os.environ.get("OPENAI_API_KEY"))
        elif frontend_model == "claude":
            openai_api_key = MODEL_API_KEYS.get("claude", os.environ.get("ANTHROPIC_API_KEY"))
        elif frontend_model == "gemini":
            openai_api_key = MODEL_API_KEYS.get("gemini", os.environ.get("GOOGLE_API_KEY"))
        elif frontend_model == "llama":
            openai_api_key = MODEL_API_KEYS.get("llama", os.environ.get("META_API_KEY"))
        else:
            openai_api_key = os.environ.get("OPENAI_API_KEY")
            
        # Check if we have the API key
        if not openai_api_key:
            print(f"⚠️ No API key found for model: {frontend_model}")
            return {"success": False, "response": f"No API key configured for model: {frontend_model}"}
        
        # Format history for KB_indexer
        formatted_history = [
            {"role": msg.role, "content": msg.content} for msg in history
        ]
        
        # Format memory for KB_indexer
        formatted_memory = memory
        
        # Use the KB_indexer module to perform the RAG query
        from KB_indexer import perform_rag_query
        
        # Get the model from cache or use a default
        model = gpt_model_cache.get(collection_name, "gpt-4o-mini")
        print(f"Using model {model} for chat with collection {collection_name}")
        
        response = perform_rag_query(
            query=message,
            base_collection_name=collection_name,
            user_collection_name=user_collection_name,
            qdrant_url=qdrant_url,
            qdrant_api_key=qdrant_api_key,
            openai_api_key=openai_api_key,
            history=formatted_history,
            memory=formatted_memory,  # Pass memory to RAG
            model=model,  # Use the stored model
            use_hybrid_search=request.use_hybrid_search,  # Pass hybrid search parameter
            system_prompt=system_prompt  # Pass the system prompt
        )
        
        return {"success": True, "response": response}
    
    except Exception as e:
        import traceback
        print(f"Error processing chat: {e}")
        print(traceback.format_exc())
        return {"success": False, "response": f"Error: {str(e)}"}

@app.get("/gpt-collection-info/{user_email}/{gpt_id}")
async def get_gpt_collection_info(user_email: str, gpt_id: str, gpt_name: str = ""):
    """
    Get the collection name for a specific GPT.
    Can be used by frontend to determine if a GPT's knowledge base is already indexed.
    """
    try:
        sanitized_email = ''.join(c if c.isalnum() else '_' for c in user_email)
        sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in gpt_name)
        
        collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
        collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}_{gpt_id}"
        collection_name = collection_name[:63]
        
        # Here you could check if the collection actually exists in Qdrant
        # For simplicity, we're just returning the constructed name
        
        return {
            "collection_name": collection_name,
            "exists": True  # In production, you'd verify this with Qdrant
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving GPT collection info: {str(e)}")

@app.post("/chat-stream")
async def chat_stream(request: ChatRequest):
    """Handle streaming chat requests with RAG support"""
    try:
        # Add query parameter validation to avoid unnecessary processing
        if not request.message or len(request.message.strip()) < 2:
            async def error_response():
                yield f'data: {{"error": "Message too short"}}\n\n'
                yield 'data: [DONE]\n\n'
            return StreamingResponse(error_response(), media_type="text/event-stream")
        
        # Pre-process history to reduce payload size
        # Only keep the last 10 messages to reduce context size
        if request.history and len(request.history) > 10:
            request.history = request.history[-10:]
        
        # Extract params from request
        message = request.message
        collection_name = request.collection_name
        user_documents = request.user_documents or []
        history = request.history or []
        memory = request.memory or []
        
        # Define user documents collection if present
        user_collection_name = f"{collection_name}_user_docs" if user_documents else None
        
        # Get the model and system prompt from cache
        cached_data = gpt_model_cache.get(collection_name, {})
        if isinstance(cached_data, str):
            # Handle legacy format where only model name was stored
            frontend_model = cached_data
            system_prompt = None
        else:
            # Handle new format with full schema
            frontend_model = cached_data.get('model', "gpt-4o-mini")
            
            # Extract system prompt from schema if available
            if 'schema' in cached_data and 'instructions' in cached_data['schema']:
                system_prompt = cached_data['schema']['instructions']
            elif 'system_prompt' in cached_data:
                system_prompt = cached_data['system_prompt']
            else:
                system_prompt = None
        
        # Append markdown enhancement to user-provided system prompt
        if system_prompt:
            if not "markdown" in system_prompt.lower():
                system_prompt += "\n\nAlways format your responses in proper markdown with appropriate headings, bullet points, tables, and emojis where relevant."
        
        # Enhance the system prompt with stronger guardrails against hallucination
        if system_prompt:
            # Add anti-hallucination guardrails if not already present
            if not "hallucinate" in system_prompt.lower():
                system_prompt = f"""
{system_prompt}

IMPORTANT GUIDELINES:
1. NEVER make up information that isn't in the provided context
2. If you don't have enough information to answer, clearly state what specific information is missing
3. Only reference documents and information that actually exist in the provided context
4. Format your response with proper markdown for readability
"""
        
        # Translate frontend model name to actual API model name
        model = MODEL_TRANSLATIONS.get(frontend_model, frontend_model)
        
        print(f"Using model {frontend_model} (API: {model}) for streaming chat with collection {collection_name}")
        if system_prompt:
            print(f"Using custom system prompt: {system_prompt[:50]}...")
        
        # Get configuration from environment
        qdrant_url = os.environ.get("QDRANT_URL")
        if not qdrant_url:
            print(f"No QDRANT_URL found in environment")
            async def error_response():
                yield f'data: {{"error": "No QDRANT_URL configured"}}\n\n'
                yield f'data: {{"done": true}}\n\n'
            return StreamingResponse(error_response(), media_type="text/event-stream")
            
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        
        # Get the appropriate API key based on model provider
        openai_api_key = os.environ.get("OPENAI_API_KEY")  # Always needed for embeddings
        
        # Get model-specific API key
        if model.startswith("gpt-"):
            model_api_key = MODEL_API_KEYS.get("gpt-4", os.environ.get("OPENAI_API_KEY"))
        elif model == "claude":
            model_api_key = MODEL_API_KEYS.get("claude", os.environ.get("ANTHROPIC_API_KEY"))
        elif model == "gemini":
            model_api_key = MODEL_API_KEYS.get("gemini", os.environ.get("GOOGLE_API_KEY"))
        elif model == "llama":
            model_api_key = MODEL_API_KEYS.get("llama", os.environ.get("META_API_KEY"))
        else:
            model_api_key = os.environ.get("OPENAI_API_KEY")
        
        # Check if we have the OpenAI API key for embeddings
        if not openai_api_key:
            print(f"No OpenAI API key found for embeddings")
            async def error_response():
                yield f'data: {{"error": "No OpenAI API key configured for embeddings"}}\n\n'
                yield f'data: {{"done": true}}\n\n'
            return StreamingResponse(error_response(), media_type="text/event-stream")
        
        # Check if we have the model-specific API key
        if not model_api_key:
            print(f"No API key found for model: {model}")
            async def error_response():
                yield f'data: {{"error": "No API key configured for model: {model}"}}\n\n'
                yield f'data: {{"done": true}}\n\n'
            return StreamingResponse(error_response(), media_type="text/event-stream")
        
        # Format history
        formatted_history = [
            {"role": msg.role, "content": msg.content} for msg in history
        ]
        
        # Format memory
        formatted_memory = memory
        
        # Use streaming implementation
        from KB_indexer import perform_rag_query_stream
        
        # Add better debugging to help diagnose the issue
        print(f"Stream request with: model={model}, collection={collection_name}")
        
        return await perform_rag_query_stream(
            query=message,
            base_collection_name=collection_name,
            user_collection_name=user_collection_name,
            qdrant_url=qdrant_url,
            qdrant_api_key=qdrant_api_key,
            openai_api_key=openai_api_key,  # For embeddings
            model_api_key=model_api_key,    # For completions with specific model
            history=formatted_history,
            memory=formatted_memory,        # Pass memory to streaming RAG
            model=model,  # Use the selected model
            top_k=3,  # Retrieve enough docs for quality responses
            use_hybrid_search=request.use_hybrid_search,  # Pass hybrid search parameter
            system_prompt=system_prompt  # Pass the system prompt
        )
    
    except Exception as e:
        import traceback
        print(f"Error processing streaming chat: {e}")
        print(traceback.format_exc())
        
        async def error_response():
            import traceback
            trace = traceback.format_exc()
            print(f"Detailed error traceback: {trace}")
            yield f'data: {{"content": "Error processing your request: {str(e)}"}}\n\n'
            yield f'data: {{"error": "Error in streaming: {str(e)}"}}\n\n'
            yield f'data: {{"done": true}}\n\n'
        
        return StreamingResponse(error_response(), media_type="text/event-stream")

@app.post("/upload-chat-files")
async def upload_chat_files(
    files: List[UploadFile] = File(...),
    user_email: str = Form(...),
    gpt_id: str = Form(...),
    gpt_name: str = Form(...),
    collection_name: str = Form(...),
    is_user_document: str = Form(default="false"),
    use_hybrid_search: bool = Form(default=False)
):
    try:
        # Initialize R2 client
        r2_client = get_r2_client()
        if not r2_client:
            raise HTTPException(status_code=500, detail="Failed to initialize R2 client")
        
        # Use a sanitized collection name for user documents
        user_collection = f"{collection_name}_user_docs" if is_user_document.lower() == 'true' else collection_name
        
        # Initialize file URLs array
        file_urls = []
            
        # Process each file
        for file in files:
            # Read file content
            content = await file.read()
            if not content:
                continue
                
            # Generate safe filename with timestamp and random component
            timestamp = int(time.time())
            file_uuid = uuid.uuid4()
            safe_filename = secure_filename(file.filename)
            r2_key = f"uploads/{user_email}/{gpt_id}/{timestamp}_{file_uuid}_{safe_filename}"
            
            # Detect MIME type
            mime_type = magic.Magic(mime=True).from_buffer(content)
                
            # Upload to R2 with 24-hour expiration
            expiration_time = datetime.now() + timedelta(hours=24)
            
            # Upload to R2
            r2_client.put_object(
                Bucket=R2_BUCKET_NAME,
                Key=r2_key,
                Body=content,
                ContentType=mime_type,
                Expires=expiration_time,
                Metadata={
                    'expiration': expiration_time.isoformat(),
                    'user_email': user_email,
                    'gpt_id': gpt_id
                }
            )
            
            # Generate public URL
            file_url = f"{R2_PUBLIC_URL}/{r2_key}"
            file_urls.append(file_url)
            
        # Start indexing process
        # Get configuration from environment
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        openai_api_key = os.environ.get("OPENAI_API_KEY")
        
        # Index files using R2 URLs with increased max_workers for faster processing
        success = KB_indexer(
            file_urls=file_urls,
            qdrant_url=qdrant_url,
            qdrant_api_key=qdrant_api_key,
            collection_name=user_collection,
            openai_api_key=openai_api_key,
            force_recreate_collection=False,  # Never recreate user document collections
            max_workers=10,  # Use more workers for faster processing
            use_hybrid_search=use_hybrid_search,  # Pass through hybrid search setting
        )
        
        if success:
            return {
                "success": True, 
                "file_urls": file_urls,
                "message": f"Successfully uploaded {len(file_urls)} files to R2 and indexed them."
            }
        else:
            return {
                "success": False,
                "file_urls": file_urls,  # Still return URLs even if indexing failed
                "message": "Files uploaded to R2, but indexing failed. They may not be searchable."
            }
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in upload_chat_files: {error_details}")
        raise HTTPException(status_code=500, detail=f"Failed to upload files: {str(e)}")

# Add a new endpoint to check processing status
@app.get("/processing-status/{task_id}")
async def get_processing_status(task_id: str):
    # Check Redis or other temporary storage for task status
    try:
        # Simplified example - in production use Redis or similar
        if task_id in processing_tasks:
            return processing_tasks[task_id]
        else:
            return {"status": "unknown", "message": "Task not found"}
    except Exception as e:
        logger.error(f"Error checking task status: {str(e)}")
        return {"status": "error", "error": str(e)}

# Global dict to track processing tasks (use Redis in production)
processing_tasks = {}

# Background processing function
async def process_files_in_background(
    saved_files, file_urls, user_email, gpt_id, gpt_name, 
    collection_name, use_hybrid_search, task_id, optimize_pdfs, max_workers
):
    try:
        # Mark as processing
        processing_tasks[task_id] = {"status": "processing", "progress": 0}
        
        # Get configuration
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        openai_api_key = os.environ.get("OPENAI_API_KEY")
        
        # Set up optimized indexing parameters for speed
        from KB_indexer import KB_indexer
        
        # For extremely fast processing, use batch operations
        use_force_recreate = False  # Don't recreate existing collections
        
        # Use optimized chunking for speed
        chunk_size = 1000 if optimize_pdfs else 500  # Larger chunks for speed
        chunk_overlap = 50  # Minimal overlap for speed
        
        # Process in thread pool
        success = await run_in_threadpool(
            lambda: KB_indexer(
                file_urls=file_urls,
                qdrant_url=qdrant_url,
                qdrant_api_key=qdrant_api_key,
                collection_name=collection_name,
                openai_api_key=openai_api_key,
                force_recreate_collection=use_force_recreate,
                max_workers=max_workers,
                use_hybrid_search=use_hybrid_search,
                fast_mode=True,  # Signal to KB_indexer that speed is priority
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        )
        
        # Update task status
        if success:
            processing_tasks[task_id] = {"status": "completed", "progress": 100}
        else:
            processing_tasks[task_id] = {"status": "failed", "error": "Indexing process failed"}
            
        # Keep status for 10 minutes then clean up
        await asyncio.sleep(600)
        if task_id in processing_tasks:
            del processing_tasks[task_id]
            
    except Exception as e:
        logger.error(f"Background processing error: {str(e)}")
        processing_tasks[task_id] = {"status": "failed", "error": str(e)}

@app.get("/hybrid-search-info")
async def hybrid_search_info():
    """
    Returns information about hybrid search support.
    Front-end can use this to determine if hybrid search is available.
    """
    try:
        # Check if fastembed package is available
        fastembed_available = False
        try:
            import importlib.util
            fastembed_spec = importlib.util.find_spec("fastembed")
            fastembed_available = fastembed_spec is not None
        except ImportError:
            pass
        
        return {
            "hybrid_search_supported": fastembed_available,
            "default_sparse_model": "Qdrant/bm25"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking hybrid search support: {str(e)}")

@app.post("/cleanup-expired-files")
async def cleanup_expired_files(api_key: str = Form(...)):
    """Cleanup files that have expired (older than 24 hours)"""
    # Simple API key validation
    if api_key != os.environ.get("CLEANUP_API_KEY"):
        raise HTTPException(status_code=403, detail="Invalid API key")
        
    try:
        r2_client = get_r2_client()
        
        # Get all objects in the uploads folder
        paginator = r2_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="uploads/")
        
        deleted_count = 0
        now = datetime.now()
        
        for page in page_iterator:
            if 'Contents' not in page:
                continue
                
            for obj in page['Contents']:
                # Check if object has expired (older than 24 hours)
                last_modified = obj['LastModified']
                age = now - last_modified.replace(tzinfo=None)  # Remove timezone info for comparison
                
                if age > timedelta(hours=24):
                    # Delete expired object
                    r2_client.delete_object(Bucket=R2_BUCKET_NAME, Key=obj['Key'])
                    deleted_count += 1
                    
        return {"success": True, "deleted_count": deleted_count}
    except Exception as e:
        logger.error(f"Error cleaning up expired files: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to clean up files: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
