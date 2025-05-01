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

# Store API keys for different models using specified env var names
MODEL_API_KEYS = {
    # OpenAI Models
    "gpt-4": os.environ.get("OPENAI_API_KEY"),
    "gpt-4o": os.environ.get("OPENAI_API_KEY"),
    "gpt-4o-mini": os.environ.get("OPENAI_API_KEY"),
    "gpt-3.5": os.environ.get("OPENAI_API_KEY"),
    "gpt-3.5-turbo": os.environ.get("OPENAI_API_KEY"),
    # Anthropic Models
    "claude": os.environ.get("ANTHROPIC_API_KEY"),
    "claude-3-opus-20240229": os.environ.get("ANTHROPIC_API_KEY"),
    # Google Models
    "gemini": os.environ.get("GEMINI_API_KEY"), # Use GEMINI_API_KEY
    "gemini-pro": os.environ.get("GEMINI_API_KEY"), # Use GEMINI_API_KEY
    # Groq Models (assuming Llama runs on Groq)
    "llama": os.environ.get("GROQ_API_KEY"),     # Use GROQ_API_KEY for llama
    "llama-3-70b-chat": os.environ.get("GROQ_API_KEY"), # Use GROQ_API_KEY
    # Add other specific model keys if needed, mapping to the correct API key env var
}

# Add a model translation dictionary (ensure keys match frontend options)
MODEL_TRANSLATIONS = {
    "gpt-4": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    "gpt-3.5": "gpt-3.5-turbo",
    "claude": "claude-3-opus-20240229",
    "gemini": "gemini-pro",
    "llama": "llama3-70b-8192" # Example: Use the actual Groq model identifier
    # Add specific translations if needed
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

# FIX: Modify ChatRequest to include necessary identifiers
class ChatRequest(BaseModel):
    message: str
    # Rename collection_name to gpt_id for clarity, assuming ID is sent
    gpt_id: str
    # Add user_email and gpt_name to reconstruct the full collection name
    user_email: str
    gpt_name: str
    history: Optional[List[Message]] = []
    memory: Optional[List[Dict[str, Any]]] = []
    user_documents: Optional[List[str]] = []
    use_hybrid_search: bool = False

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
        model = request.schema.get('model')  # Don't set a default
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
        # FIX: Reconstruct the collection_name consistently
        sanitized_email = ''.join(c if c.isalnum() else '_' for c in request.user_email)
        sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in request.gpt_name)
        collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
        # Use gpt_id from the request here
        collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}_{request.gpt_id}"
        collection_name = collection_name[:63] # Ensure length limit
        
        user_documents = request.user_documents or []
        history = request.history or []
        memory = request.memory or []
        
        # Define user documents collection if present (using the reconstructed name)
        user_collection_name = None
        if user_documents:
            # Check both possible formats of collection names (with and without prefix)
            user_collection_with_prefix = f"{collection_name}_user_docs"
            user_collection_without_prefix = f"{request.gpt_id}_user_docs"
            
            # Prefer collection with documents if available
            try:
                from KB_indexer import check_collection_exists
                if check_collection_exists(qdrant_url, qdrant_api_key, user_collection_with_prefix):
                    user_collection_name = user_collection_with_prefix
                elif check_collection_exists(qdrant_url, qdrant_api_key, user_collection_without_prefix):
                    user_collection_name = user_collection_without_prefix
                else:
                    # Default to standard format
                    user_collection_name = user_collection_with_prefix
            except Exception as e:
                # Fall back to standard format if check fails
                print(f"Error checking collections: {e}")
                user_collection_name = user_collection_with_prefix
        
        # Get the model and system prompt from cache
        cached_data = gpt_model_cache.get(collection_name, {})
        frontend_model = None # Initialize
        system_prompt = None
        if isinstance(cached_data, dict):
            frontend_model = cached_data.get('model')
            system_prompt = cached_data.get('system_prompt')
        elif isinstance(cached_data, str): # Handle legacy cache format
             frontend_model = cached_data

        if not frontend_model:
            error_msg = f"No model configured or found in cache for collection: {collection_name}"
            print(f"⚠️ {error_msg}")
            return {"success": False, "response": error_msg}
            
        # Translate frontend model name to actual API model name
        # Use frontend_model as default if no translation exists
        model = MODEL_TRANSLATIONS.get(frontend_model, frontend_model)
        
        print(f"🤖 Using model {frontend_model} (API Target: {model}) for chat with collection {collection_name}")
        if system_prompt:
            print(f"📝 Using custom system prompt: {system_prompt[:50]}...")
        
        # Get configuration from environment
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        # Key for embeddings - assumed to be OpenAI for now
        openai_embedding_key = os.environ.get("OPENAI_API_KEY") 

        # Get the appropriate API key for the *selected model*
        # Use the frontend_model name to look up the key in the updated MODEL_API_KEYS
        model_api_key = MODEL_API_KEYS.get(frontend_model)
        
        # Check if we have the specific API key for the selected model
        if not model_api_key:
            # Try matching based on prefix (e.g., gpt-4o maps to gpt-4 key)
            if frontend_model.startswith("gpt-"):
                model_api_key = MODEL_API_KEYS.get("gpt-4") # Or specific version if needed
            # Add similar logic for other prefixes if necessary
            
            # If still not found, log an error
            if not model_api_key:
                error_msg = f"No API key configured in environment for model: {frontend_model}"
                print(f"⚠️ {error_msg}")
                print(f"   Checked MODEL_API_KEYS with key: '{frontend_model}'")
                return {"success": False, "response": error_msg}

        # Check if we have the OpenAI key needed for embeddings
        if not openai_embedding_key:
             error_msg = "OpenAI API key for embeddings is missing in environment (OPENAI_API_KEY)."
             print(f"⚠️ {error_msg}")
             return {"success": False, "response": error_msg}

        # Format history for KB_indexer
        formatted_history = [
            {"role": msg.role, "content": msg.content} for msg in history
        ]
        
        # Format memory for KB_indexer
        formatted_memory = memory
        
        # Use the KB_indexer module to perform the RAG query
        from KB_indexer import perform_rag_query
        
        # Pass the correct API key and model name
        response = perform_rag_query(
            query=message,
            base_collection_name=collection_name,
            user_collection_name=user_collection_name,
            qdrant_url=qdrant_url,
            qdrant_api_key=qdrant_api_key,
            openai_api_key=openai_embedding_key, # Key for embeddings
            model_api_key=model_api_key,      # Key for the specific LLM
            history=formatted_history,
            memory=formatted_memory,
            model=model,                      # Translated API model name
            use_hybrid_search=request.use_hybrid_search,
            system_prompt=system_prompt
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
        # FIX: Reconstruct the collection_name consistently
        sanitized_email = ''.join(c if c.isalnum() else '_' for c in request.user_email)
        sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in request.gpt_name)
        collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
        # Use gpt_id from the request here
        collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}_{request.gpt_id}"
        collection_name = collection_name[:63] # Ensure length limit
        
        user_documents = request.user_documents or []
        history = request.history or []
        memory = request.memory or []
        
        # Get configuration from environment FIRST (fix scope issue)
        qdrant_url = os.environ.get("QDRANT_URL")
        if not qdrant_url:
            print(f"No QDRANT_URL found in environment")
            async def error_response():
                yield f'data: {{"error": "No QDRANT_URL configured"}}\n\n'
                yield f'data: {{"done": true}}\n\n'
            return StreamingResponse(error_response(), media_type="text/event-stream")
            
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        
        # Define user documents collection if present
        user_collection_name = None
        if user_documents:
            # First try the exact ID format that was actually indexed
            direct_user_collection = f"{request.gpt_id}_user_docs"
            
            # Import this only if needed to check collections
            from KB_indexer import check_collection_exists
            
            try:
                # Try direct ID format first (this matches what we saw in logs)
                if check_collection_exists(qdrant_url, qdrant_api_key, direct_user_collection):
                    user_collection_name = direct_user_collection
                    print(f"✅ Found user collection: {user_collection_name}")
                # Fallback to collection name format
                elif check_collection_exists(qdrant_url, qdrant_api_key, f"{collection_name}_user_docs"):
                    user_collection_name = f"{collection_name}_user_docs"
                    print(f"✅ Found user collection: {user_collection_name}")
                else:
                    print(f"⚠️ No user collection found, using default: {direct_user_collection}")
                    user_collection_name = direct_user_collection
            except Exception as e:
                print(f"Error checking collections: {e}")
                user_collection_name = direct_user_collection
        
        # Get the model and system prompt from cache
        cached_data = gpt_model_cache.get(collection_name, {})
        frontend_model = None # Initialize
        system_prompt = None
        if isinstance(cached_data, dict):
            frontend_model = cached_data.get('model')
            system_prompt = cached_data.get('system_prompt')
        elif isinstance(cached_data, str): # Handle legacy cache format
             frontend_model = cached_data

        if not frontend_model:
            error_msg = f"No model configured or found in cache for collection: {collection_name}"
            print(f"⚠️ {error_msg}")
            async def error_stream():
                 yield f'data: {{"error": "{error_msg}"}}\n\n'
                 yield f'data: {{"done": true}}\n\n'
            return StreamingResponse(error_stream(), media_type="text/event-stream")
            
        # Translate frontend model name to actual API model name
        # Use frontend_model as default if no translation exists
        model = MODEL_TRANSLATIONS.get(frontend_model, frontend_model)
        
        print(f"Using model {frontend_model} (API Target: {model}) for streaming chat with collection {collection_name}")
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
        
        # Key for embeddings - assumed to be OpenAI for now
        openai_embedding_key = os.environ.get("OPENAI_API_KEY") 
        
        # Get the appropriate API key for the *selected model*
        model_api_key = MODEL_API_KEYS.get(frontend_model)
        
        # Check if we have the specific API key for the selected model
        if not model_api_key:
            # Try matching based on prefix (e.g., gpt-4o maps to gpt-4 key)
            if frontend_model.startswith("gpt-"):
                model_api_key = MODEL_API_KEYS.get("gpt-4") # Or specific version if needed
            # Add similar logic for other prefixes if necessary

            if not model_api_key:
                error_msg = f"No API key configured in environment for model: {frontend_model}"
                print(f"⚠️ {error_msg}")
                print(f"   Checked MODEL_API_KEYS with key: '{frontend_model}'")
                async def error_stream_key():
                    yield f'data: {{"error": "{error_msg}"}}\n\n'
                    yield f'data: {{"done": true}}\n\n'
                return StreamingResponse(error_stream_key(), media_type="text/event-stream")

        # Check if we have the OpenAI key needed for embeddings
        if not openai_embedding_key:
             error_msg = "OpenAI API key for embeddings is missing in environment (OPENAI_API_KEY)."
             print(f"⚠️ {error_msg}")
             async def error_stream_emb():
                 yield f'data: {{"error": "{error_msg}"}}\n\n'
                 yield f'data: {{"done": true}}\n\n'
             return StreamingResponse(error_stream_emb(), media_type="text/event-stream")
        
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
            openai_api_key=openai_embedding_key, # Key for embeddings
            model_api_key=model_api_key,         # Key for the specific LLM
            history=formatted_history,
            memory=formatted_memory,
            model=model,                         # Translated API model name
            top_k=3,
            use_hybrid_search=request.use_hybrid_search,
            system_prompt=system_prompt
        )
    
    except Exception as e:
        import traceback
        print(f"Error processing streaming chat: {e}")
        print(traceback.format_exc())
        
        # FIX: Re-apply fix for error response generator
        error_message = str(e).replace('"', '\\"').replace('\n', '\\n') # Basic escaping
        # Define the generator to accept the error message
        async def error_response_gen(err_msg: str): 
            trace = traceback.format_exc().replace('"', '\\"').replace('\n', '\\n')
            print(f"Detailed error traceback: {trace}")
            yield f'data: {{"content": "Error processing your request: {err_msg}"}}\n\n'
            yield f'data: {{"error": "Error in streaming: {err_msg}"}}\n\n'
            yield f'data: {{"done": true}}\n\n'
        
        # Call the generator with the captured error message
        return StreamingResponse(error_response_gen(error_message), media_type="text/event-stream")

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
