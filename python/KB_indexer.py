# --- Final Production Code ---

import io
import os
import requests
import concurrent.futures
import logging
import time
from typing import List, Dict, Any, Optional

# Qdrant
import qdrant_client
from qdrant_client.http.models import Distance, VectorParams, PointStruct, CollectionStatus, OptimizersConfigDiff, HnswConfigDiff, SparseVectorParams

# LangChain components
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_qdrant import Qdrant, FastEmbedSparse, RetrievalMode, QdrantVectorStore
from langchain_openai import OpenAIEmbeddings # Use OpenAI embeddings

# File Parsers
import pdfplumber
from docx import Document as DocxDocument

# Add these imports at the top of the file
from fastapi import WebSocket
from fastapi.responses import StreamingResponse
import asyncio
import aiohttp
import json

# Setup robust logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("kb_indexer.log"), # Log to a file
        logging.StreamHandler() # Log to console
    ]
)
logger = logging.getLogger(__name__)

# --- Constants ---
# Dimension for OpenAI's text-embedding-3-small
OPENAI_EMBEDDING_DIMENSION = 1536
# Default Qdrant distance metric suitable for OpenAI embeddings
QDRANT_DISTANCE_METRIC = Distance.COSINE
# Default sparse embedding model
DEFAULT_SPARSE_MODEL = "Qdrant/bm25"

# --- Helper Function to Parse Files ---
def parse_file_content(content: bytes, filename: str) -> Optional[str]:
    """Parses content based on filename extension."""
    logger.debug(f"Parsing file: {filename}")
    try:
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext == '.pdf':
            text = ""
            # Using BytesIO for in-memory processing
            with io.BytesIO(content) as pdf_stream:
                with pdfplumber.open(pdf_stream) as pdf:
                    # Handle potential empty pages or extract errors gracefully
                    for page_num, page in enumerate(pdf.pages):
                         page_text = page.extract_text()
                         if page_text:
                             text += page_text + "\n"
                         else:
                             logger.debug(f"No text extracted from page {page_num + 1} of {filename}")
            logger.debug(f"Finished parsing PDF: {filename}")
            return text.strip() if text else None # Return None if empty
        elif file_ext == '.docx':
             # Using BytesIO for in-memory processing
            with io.BytesIO(content) as docx_stream:
                doc = DocxDocument(docx_stream)
                text = "\n".join(para.text for para in doc.paragraphs if para.text)
            logger.debug(f"Finished parsing DOCX: {filename}")
            return text.strip() if text else None # Return None if empty
        elif file_ext == '.txt':
            # Attempt decoding with UTF-8, replace errors
            text = content.decode('utf-8', errors='replace')
            logger.debug(f"Finished parsing TXT: {filename}")
            return text.strip() if text else None # Return None if empty
        else:
            logger.warning(f"Unsupported file type: {filename}. Skipping.")
            return None
    except Exception as e:
        logger.error(f"Error parsing file {filename}: {e}", exc_info=True) # Log traceback
        return None

# --- Helper Function to Process a Single File ---
def process_local_file(file_path: str, splitter: RecursiveCharacterTextSplitter) -> List[Document]:
    """Process local files without downloading them"""
    documents = []
    try:
        logger.info(f"Processing local file: {file_path}")
        
        # Check if file exists and is accessible
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logger.error(f"Local file not found or not accessible: {file_path}")
            return []
            
        # Read file directly from disk
        with open(file_path, 'rb') as f:
            content = f.read()
            
        if not content:
            logger.warning(f"Local file is empty: {file_path}")
            return []
            
        filename = os.path.basename(file_path)
        extracted_text = parse_file_content(content, filename)
        
        if extracted_text:
            # Use the splitter to create chunks
            chunks = splitter.split_text(extracted_text)
            # Create LangChain Document objects with metadata
            for i, chunk in enumerate(chunks):
                doc = Document(
                    page_content=chunk,
                    metadata={
                        "source": file_path,
                        "filename": filename,
                        "chunk_index": i,
                        "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                )
                documents.append(doc)
            logger.info(f"Successfully chunked {filename} into {len(documents)} documents.")
        else:
            logger.warning(f"No text could be extracted from {filename}.")
            
    except Exception as e:
        logger.error(f"An unexpected error occurred processing local file {file_path}: {e}", exc_info=True)
        
    return documents

def process_single_file(file_url: str, splitter: RecursiveCharacterTextSplitter) -> List[Document]:
    """Downloads, parses, and chunks a single file."""
    # Check if it's a local file (starts with http or not)
    if not file_url.startswith(('http://', 'https://')):
        # Handle as local file
        return process_local_file(file_url, splitter)
        
    # Rest of the existing function for remote files
    documents = []
    try:
        logger.info(f"Processing remote file: {file_url}")
        # Increased timeout for potentially large files - INCREASE TIMEOUT
        response = requests.get(file_url, timeout=30)  # Reduced from 120 to 30 seconds
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # More robust filename extraction from URL
        try:
            # Attempt to get filename from Content-Disposition header first
            content_disposition = response.headers.get('Content-Disposition')
            if content_disposition:
                import re
                fname = re.findall('filename="?(.+)"?', content_disposition)
                if fname:
                    filename = fname[0]
                else: # Fallback if header is malformed
                    filename = os.path.basename(file_url.split('?')[0].split('/')[-1])

            else: # Fallback to URL path component
                 filename = os.path.basename(file_url.split('?')[0].split('/')[-1])

            # Handle cases where filename might be empty or just '/'
            if not filename or filename == '/':
                filename = f"unknown_file_{time.time()}" # Generate a placeholder
                logger.warning(f"Could not determine filename for {file_url}, using placeholder: {filename}")

        except Exception as e:
             logger.warning(f"Error extracting filename for {file_url}, using fallback. Error: {e}")
             filename = f"unknown_file_{time.time()}" # Generate a placeholder


        content = response.content
        if not content:
             logger.warning(f"Downloaded file {filename} ({file_url}) is empty. Skipping.")
             return []

        extracted_text = parse_file_content(content, filename)

        if extracted_text:
            # Use the splitter to create chunks
            chunks = splitter.split_text(extracted_text)
            # Create LangChain Document objects with metadata
            for i, chunk in enumerate(chunks):
                doc = Document(
                    page_content=chunk,
                    metadata={
                        "source": file_url,
                        "filename": filename,
                        "chunk_index": i,
                        "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) # Add timestamp
                    }
                )
                documents.append(doc)
            logger.info(f"Successfully chunked {filename} into {len(documents)} documents.")
        else:
             logger.warning(f"No text could be extracted from {filename} ({file_url}).")


    except requests.exceptions.Timeout:
        logger.error(f"Timeout while downloading {file_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download or access {file_url}: {e}")
    except Exception as e:
        # Catch any other unexpected errors during processing
        logger.error(f"An unexpected error occurred processing {file_url}: {e}", exc_info=True)

    return documents

# --- Main Indexer Function ---
def KB_indexer(
    file_urls: List[str],
    qdrant_url: str,
    qdrant_api_key: Optional[str],
    collection_name: str,
    openai_api_key: Optional[str] = None,
    force_recreate_collection: bool = False,
    max_workers: int = 15,  # Increased from 10 to 15 for more parallelism
    use_hybrid_search: bool = False,  # Add parameter to enable hybrid search
    system_prompt: Optional[str] = None,
    schema: Optional[Dict] = None
) -> bool:
    """
    Indexes files from URLs into a Qdrant collection using OpenAI embeddings
    (text-embedding-3-small) and parallel processing.

    Relies on the OPENAI_API_KEY environment variable if openai_api_key argument is None.

    Args:
        file_urls: List of URLs pointing to the files (PDF, DOCX, TXT).
        qdrant_url: URL of the Qdrant instance (e.g., "http://localhost:6333").
        qdrant_api_key: API key for Qdrant Cloud or secured instances. None if not needed.
        collection_name: Name of the Qdrant collection (e.g., user_email+gpt_name).
                         Should be unique per knowledge base.
        openai_api_key: Optional OpenAI API Key. If None, reads from OPENAI_API_KEY env var.
        force_recreate_collection: If True, deletes the collection if it exists before indexing.
                                   Use with caution in production.
        max_workers: Maximum number of parallel threads for downloading/parsing files.
        use_hybrid_search: If True, enables hybrid search with dense and sparse vectors.
        system_prompt: Optional system prompt for the collection
        schema: Optional schema for the collection

    Returns:
        True if the indexing process completed successfully (even if some files failed).
        False if a critical error occurred (Qdrant connection, collection setup, embedding failure).
    """
    start_time = time.time()
    logger.info(f"Starting indexing process for collection: {collection_name}")
    logger.info(f"Processing {len(file_urls)} file(s).")
    if not file_urls:
        logger.warning("No file URLs provided. Exiting.")
        return True # Nothing to do, considered successful

    # 1. Initialize OpenAI Embeddings
    try:
        # Reads OPENAI_API_KEY env var by default if api_key is None
        # Specify the model explicitly
        embedding_model = OpenAIEmbeddings(
            model="text-embedding-3-small",
            api_key=openai_api_key, # Pass key if provided, else None (reads from env)
            # Consider adding request_timeout if needed
            # request_timeout=60,
            chunk_size=1500  # Increased from 1000 to 1500
        )
        # Optional: Perform a quick test embed to catch auth errors early
        # embedding_model.embed_query("test")
        logger.info("OpenAI embedding model initialized for 'text-embedding-3-small'.")
        
        # Initialize sparse embeddings if hybrid search is enabled
        sparse_embedding_model = None
        if use_hybrid_search:
            try:
                sparse_embedding_model = FastEmbedSparse(model_name=DEFAULT_SPARSE_MODEL)
                logger.info(f"Sparse embedding model initialized using FastEmbedSparse with {DEFAULT_SPARSE_MODEL} model.")
            except Exception as se:
                logger.error(f"Failed to initialize sparse embedding model: {se}", exc_info=True)
                logger.warning("Continuing with dense embeddings only.")
                use_hybrid_search = False
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI embedding model: {e}", exc_info=True)
        logger.error("Ensure OPENAI_API_KEY environment variable is set correctly or passed as an argument.")
        return False

    # 2. Initialize Qdrant Client
    try:
        client = qdrant_client.QdrantClient(
            url=qdrant_url,
            api_key=qdrant_api_key,
            timeout=60.0 # Increase timeout for potentially long operations
            # prefer_grpc=True, # Consider enabling for performance if network allows and server supports it
        )
        # Check connection by performing a simple operation instead of health_check
        try:
            # Try to list collections as a way to verify connection
            client.get_collections()
            logger.info(f"Qdrant client initialized and connection verified to {qdrant_url}.")
        except Exception as e:
            logger.error(f"Failed to verify Qdrant connection at {qdrant_url}: {e}", exc_info=True)
            raise
    except Exception as e:
        logger.error(f"Failed to initialize Qdrant client at {qdrant_url}: {e}", exc_info=True)
        return False # Indicate failure

    # 3. Check/Create Qdrant Collection
    try:
        vector_size = OPENAI_EMBEDDING_DIMENSION # Use constant
        collection_exists = False
        try:
            collection_info = client.get_collection(collection_name=collection_name)
            if collection_info:
                collection_exists = True
                logger.info(f"Collection '{collection_name}' already exists.")
                
                # For debugging - print the actual structure
                logger.info(f"Collection info structure: {dir(collection_info)}")
                if hasattr(collection_info, 'config'):
                    logger.info(f"Config attributes: {dir(collection_info.config)}")
                    if hasattr(collection_info.config, 'params'):
                        logger.info(f"Params attributes: {dir(collection_info.config.params)}")
                
                # Try multiple approaches to get vector size based on different Qdrant client versions
                existing_vector_size = -1
                
                # Attempt to get vector size from various possible structures
                try:
                    # For Qdrant client v1.1.1+
                    if hasattr(collection_info, 'config') and hasattr(collection_info.config, 'params'):
                        # Check for 'size' attribute in params
                        if hasattr(collection_info.config.params, 'size'):
                            existing_vector_size = collection_info.config.params.size
                        # Or if it has vectors_config attribute
                        elif hasattr(collection_info.config.params, 'vectors_config'):
                            vectors_config = collection_info.config.params.vectors_config
                            if isinstance(vectors_config, dict) and 'size' in vectors_config:
                                existing_vector_size = vectors_config['size']
                
                    # For Qdrant client v1.2.0+
                    elif hasattr(collection_info, 'vectors_config'):
                        if isinstance(collection_info.vectors_config, dict):
                            # Try to get default vector config
                            for vector_name, vector_config in collection_info.vectors_config.items():
                                if hasattr(vector_config, 'size'):
                                    existing_vector_size = vector_config.size
                                    break
                
                    logger.info(f"Detected vector size: {existing_vector_size}")
                    
                    # If we couldn`t determine the vector size, log warning but continue
                    if existing_vector_size == -1:
                        logger.warning(f"Could not determine vector size for collection '{collection_name}'. Continuing with assumption it's compatible.")
                        # For safety, assume it's compatible rather than recreating
                        existing_vector_size = vector_size
                
                except Exception as vector_size_err:
                    logger.warning(f"Error determining vector size: {vector_size_err}. Continuing with assumption it's compatible.")
                    existing_vector_size = vector_size  # Assume it's the right size

                if force_recreate_collection:
                    logger.warning(f"Recreating collection '{collection_name}' as force_recreate_collection is True.")
                    client.delete_collection(collection_name=collection_name, timeout=120)
                    # Short pause after deletion before recreation
                    time.sleep(2)
                    collection_exists = False
                elif existing_vector_size != vector_size:
                     logger.error(f"Collection '{collection_name}' exists but has incorrect vector size "
                                  f"({existing_vector_size})! Expected {vector_size} for 'text-embedding-3-small'. "
                                  f"Cannot proceed. Use force_recreate_collection=True or delete/migrate manually.")
                     return False # Stop for safety

        except qdrant_client.http.exceptions.UnexpectedResponse as e:
             # Specifically catch 404 Not Found
             if hasattr(e, 'status_code') and e.status_code == 404:
                 logger.info(f"Collection '{collection_name}' does not exist. Will be created.")
                 collection_exists = False
             else: # Re-raise other unexpected errors
                 raise e
        except Exception as e:
             # Catch potential connection errors or other client issues during get_collection
             logger.error(f"Error checking collection '{collection_name}': {e}", exc_info=True)
             return False


        if not collection_exists:
            if use_hybrid_search and sparse_embedding_model:
                logger.info(f"Creating collection '{collection_name}' with both dense and sparse vector support.")
                # Create collection with both dense and sparse vector support
                client.create_collection(
                    collection_name=collection_name,
                    vectors_config={
                        "dense": VectorParams(size=vector_size, distance=QDRANT_DISTANCE_METRIC)
                    },
                    sparse_vectors_config={
                        "sparse": SparseVectorParams()
                    },
                    optimizers_config=OptimizersConfigDiff(memmap_threshold=20000),
                    hnsw_config=HnswConfigDiff(m=16, ef_construct=100)
                )
            else:
                logger.info(f"Creating collection '{collection_name}' with dense vector size {vector_size} and distance {QDRANT_DISTANCE_METRIC}.")
                client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(size=vector_size, distance=QDRANT_DISTANCE_METRIC),
                    # Optional: Add optimizer/indexing parameters for production performance
                    optimizers_config=OptimizersConfigDiff(memmap_threshold=20000), # Example: Adjust based on expected data size
                    hnsw_config=HnswConfigDiff(m=16, ef_construct=100) # Example: HNSW parameters, tune as needed
                )
            # Wait briefly for collection to likely become active
            time.sleep(2)
            logger.info(f"Collection '{collection_name}' created.")

    except Exception as e:
        logger.error(f"Error during Qdrant collection setup for '{collection_name}': {e}", exc_info=True)
        return False

    # 4. Initialize Text Splitter
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1200,  # Increased from 800 to 1200
        chunk_overlap=150,  # Increased from 120 to 150
        length_function=len,
        is_separator_regex=False,
    )

    # 5. Process Files in Parallel
    all_documents: List[Document] = []
    processed_files_count = 0
    failed_files: List[str] = []

    # Adjust max_workers based on system resources and network latency
    actual_max_workers = min(max_workers, len(file_urls) if file_urls else 1)
    logger.info(f"Using up to {actual_max_workers} parallel workers for file processing.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_max_workers) as executor:
        future_to_url = {executor.submit(process_single_file, url, text_splitter): url for url in file_urls}

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                documents_from_file = future.result() # Get the list of Document objects
                if documents_from_file:
                    all_documents.extend(documents_from_file)
                    processed_files_count += 1
                else:
                    # Log files that yielded no documents (might indicate parse failure or empty file)
                    logger.warning(f"File {url} resulted in zero documents.")
                    # We might still count it as processed, but failed to extract content
                    failed_files.append(url)

            except Exception as e:
                # Log exceptions raised from within process_single_file if not caught there
                logger.error(f"Error retrieving result for URL {url}: {e}", exc_info=True)
                failed_files.append(url)


    logger.info(f"Finished processing files. Successful: {processed_files_count}, Failed/Empty: {len(failed_files)}.")
    if failed_files:
        logger.warning(f"URLs that failed or yielded no content: {failed_files}")

    if not all_documents:
        logger.warning("No documents were generated from the provided URLs. Nothing to index.")
        total_time = time.time() - start_time
        logger.info(f"Indexing process completed in {total_time:.2f} seconds (no documents indexed).")
        # Return True because the process itself didn't hit a critical error, just no data
        return True

    logger.info(f"Total document chunks generated from all files: {len(all_documents)}")

    # 6. Embed and Upsert documents into Qdrant
    try:
        logger.info(f"Starting embedding and upserting into collection '{collection_name}'...")

        # Use Langchain's Qdrant wrapper for convenience
        if use_hybrid_search and sparse_embedding_model:
            # Initialize with both dense and sparse embeddings for hybrid search
            logger.info("Initializing QdrantVectorStore with hybrid search support")
            qdrant_vector_store = QdrantVectorStore(
                client=client,
                collection_name=collection_name,
                embedding=embedding_model,
                sparse_embedding=sparse_embedding_model,
                retrieval_mode=RetrievalMode.HYBRID,
                vector_name="dense",
                sparse_vector_name="sparse",
            )
        else:
            # Standard dense-only initialization
            qdrant_vector_store = QdrantVectorStore(
                client=client,
                collection_name=collection_name,
                embedding=embedding_model,
            )

        # add_documents handles embedding calls to OpenAI and upserting to Qdrant
        # It returns the list of Qdrant point IDs added
        ids = qdrant_vector_store.add_documents(all_documents, ids=None) # Let Qdrant generate IDs

        logger.info(f"Successfully upserted {len(ids)} vectors into collection '{collection_name}'.")
        total_time = time.time() - start_time
        logger.info(f"Indexing process completed successfully in {total_time:.2f} seconds.")

        # Add logic to store system_prompt and schema in metadata
        # Rest of the function remains the same
        return True # Indicate success

    except Exception as e:
        # Catch potential errors during embedding (e.g., OpenAI API errors) or upserting
        logger.error(f"CRITICAL: Failed to embed and upsert documents into Qdrant collection '{collection_name}': {e}", exc_info=True)
        total_time = time.time() - start_time
        logger.error(f"Indexing process failed after {total_time:.2f} seconds during embedding/upserting.")
        return False # Indicate failure

# --- RAG Query Functions ---
def retrieve_documents(
    query: str,
    qdrant_url: str,
    qdrant_api_key: Optional[str],
    collection_name: str,
    openai_api_key: Optional[str] = None,
    top_k: int = 3,
    prefix: str = "",
    use_hybrid_search: bool = False
) -> List[Document]:
    """
    Retrieves relevant documents from a Qdrant collection using the query.
    """
    logger.info(f"Retrieving documents from collection: {collection_name}")
    
    try:
        # Initialize client
        client = qdrant_client.QdrantClient(
            url=qdrant_url,
            api_key=qdrant_api_key,
            timeout=60.0
        )
        
        # Check if collection exists before attempting to retrieve
        try:
            client.get_collection(collection_name=collection_name)
        except qdrant_client.http.exceptions.UnexpectedResponse as e:
            # Check if it's a 404 error (collection not found)
            if hasattr(e, 'status_code') and e.status_code == 404:
                logger.warning(f"Collection {collection_name} does not exist. Returning empty results.")
                return []
            else:
                # If it's another type of error, re-raise
                raise
        
        # Continue with normal processing if collection exists
        # Initialize embeddings model
        embedding_model = OpenAIEmbeddings(
            model="text-embedding-3-small",
            api_key=openai_api_key,
        )
        
        # Create vector store
        if use_hybrid_search:
            # Initialize sparse embeddings for hybrid search
            try:
                sparse_embedding_model = FastEmbedSparse(model_name=DEFAULT_SPARSE_MODEL)
                logger.info(f"Using hybrid search with dense and sparse embeddings ({DEFAULT_SPARSE_MODEL})")
                
                vector_store = QdrantVectorStore(
                    client=client,
                    collection_name=collection_name,
                    embedding=embedding_model,
                    sparse_embedding=sparse_embedding_model,
                    retrieval_mode=RetrievalMode.HYBRID,
                    vector_name="dense",
                    sparse_vector_name="sparse",
                )
            except Exception as e:
                logger.warning(f"Failed to initialize sparse embeddings: {e}. Falling back to dense search.")
                vector_store = QdrantVectorStore(
                    client=client,
                    collection_name=collection_name,
                    embedding=embedding_model
                )
        else:
            # Standard dense-only initialization
            vector_store = QdrantVectorStore(
                client=client,
                collection_name=collection_name,
                embedding=embedding_model
            )
        
        # Search for similar documents
        retrieved_docs = vector_store.similarity_search(query, k=top_k)
        
        # Add prefix to document content if provided
        if prefix:
            for doc in retrieved_docs:
                doc.page_content = f"{prefix} {doc.page_content}"
        
        logger.info(f"Retrieved {len(retrieved_docs)} documents from {collection_name}")
        return retrieved_docs
        
    except Exception as e:
        logger.error(f"Error retrieving documents from {collection_name}: {e}", exc_info=True)
        return []

# Modify the perform_rag_query_stream function to support multiple models
async def perform_rag_query_stream(
    query: str,
    base_collection_name: str,
    user_collection_name: Optional[str], 
    qdrant_url: str,
    qdrant_api_key: Optional[str],
    openai_api_key: Optional[str],
    model_api_key: Optional[str] = None,
    history: List[Dict[str, str]] = None,
    memory: List[Dict[str, str]] = None,
    model: str = "gpt-4o-mini",
    top_k: int = 3,
    use_hybrid_search: bool = False,
    system_prompt: Optional[str] = None  # Add system prompt parameter
) -> StreamingResponse:
    logger.info(f"Performing streaming RAG query using model: {model}")
    history = history or []
    
    # Process memory to enhance context
    memory_context = ""
    if memory and len(memory) > 0:
        # Format recent memory items (limited to last 10 to avoid token bloat)
        recent_memory = memory[-10:] if len(memory) > 10 else memory
        memory_context = "Previous conversation context:\n"
        for i, msg in enumerate(recent_memory):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            memory_context += f"[{role}]: {content}\n"
        memory_context += "\n"
    
    # Determine provider based on model name
    provider = "openai"  # Default provider
    if model.startswith("claude"):
        provider = "anthropic"
    elif model.startswith("gemini"):
        provider = "google"
    elif model.startswith("llama"):
        provider = "meta"
        
    logger.info(f"Using {provider} provider for model: {model}")
    
    try:
        # Get documents from both collections if they exist
        base_docs = []
        try:
            base_docs = retrieve_documents(
                query=query,
                qdrant_url=qdrant_url,
                qdrant_api_key=qdrant_api_key,
                collection_name=base_collection_name,
                openai_api_key=openai_api_key,
                top_k=top_k,
                prefix="Knowledge Base",
                use_hybrid_search=use_hybrid_search
            )
        except Exception as e:
            logger.warning(f"Error retrieving from base collection: {str(e)}")
        
        user_docs = []
        if user_collection_name:
            try:
                user_docs = retrieve_documents(
                    query=query,
                    qdrant_url=qdrant_url,
                    qdrant_api_key=qdrant_api_key,
                    collection_name=user_collection_name,
                    openai_api_key=openai_api_key,
                    top_k=top_k,
                    prefix="User Uploaded",
                    use_hybrid_search=use_hybrid_search
                )
            except Exception as e:
                logger.warning(f"Error retrieving from user collection: {str(e)}")
        
        # Combine docs, prioritizing user docs
        all_docs = user_docs + base_docs
        
        # Prepare context from retrieved documents
        context = ""
        if all_docs:
            context = "Relevant information:\n\n"
            for i, doc in enumerate(all_docs[:top_k*2]): # Limit to avoid token issues
                source = doc.metadata.get("source", "Unknown")
                page = doc.metadata.get("page", "")
                page_info = f", page {page}" if page else ""
                context += f"[Document {i+1} - {source}{page_info}]\n{doc.page_content}\n\n"
        
        # Use system prompt from frontend if available, otherwise use a generic one
        if system_prompt:
            system_message = system_prompt
        else:
            # Adjust system message based on context available
            if all_docs:
                system_message = f"""You are a helpful assistant answering questions based on the provided documents.
Use the information from the documents to provide accurate and helpful responses.
If the documents don't contain relevant information to answer the question, say so and provide your best general knowledge answer.
{memory_context if memory_context else ""}"""
            else:
                system_message = f"""You are a helpful assistant answering questions based on your knowledge.
The user may have expected you to have access to specific documents, but they couldn't be retrieved or don't exist.
Please answer based on your general knowledge and be transparent about not having access to specific documents if relevant.
{memory_context if memory_context else ""}"""
        
        # Format conversation history for the API
        messages = []
        
        # Add system message
        messages.append({"role": "system", "content": system_message})
        
        # Add context as a system message if available
        if context:
            messages.append({
                "role": "system",
                "content": f"Additional context for answering the user's question: {context}"
            })
        
        # Add conversation history
        for message in history:
            messages.append({
                "role": message["role"],
                "content": message["content"]
            })
        
        # Add the current query
        messages.append({"role": "user", "content": query})
        
        # Streaming response
        async def streaming_response():
            async with aiohttp.ClientSession() as session:
                # Configure API endpoint and payload based on provider
                if provider == "openai":
                    api_url = "https://api.openai.com/v1/chat/completions"
                    payload = {
                        "model": model,
                        "messages": messages,
                        "stream": True
                    }
                    headers = {
                        "Authorization": f"Bearer {openai_api_key}",
                        "Content-Type": "application/json"
                    }
                else:
                    # Default to OpenAI API for all other providers for now
                    api_url = "https://api.openai.com/v1/chat/completions"
                    fallback_model = "gpt-4o-mini"  # Use a reliable fallback model
                    logger.info(f"Using OpenAI fallback model {fallback_model} instead of {provider}")
                    
                    payload = {
                        "model": fallback_model,
                        "messages": messages,
                        "stream": True
                    }
                    headers = {
                        "Authorization": f"Bearer {openai_api_key}",
                        "Content-Type": "application/json"
                    }
                    
                async with session.post(api_url, headers=headers, json=payload) as response:
                    if not response.ok:
                        error_msg = f"API error: {response.status} - {await response.text()}"
                        logger.error(error_msg)
                        yield f"data: {json.dumps({'error': error_msg})}\n\n"
                        yield f"data: {json.dumps({'done': True})}\n\n"
                        return
                        
                    async for line in response.content:
                        if line.startswith(b"data: "):
                            line = line[6:].strip()
                            if line == b"[DONE]":
                                yield f"data: {json.dumps({'done': True})}\n\n"
                                break
                            try:
                                data = json.loads(line)
                                if "choices" in data and len(data["choices"]) > 0:
                                    delta = data["choices"][0].get("delta", {})
                                    content = delta.get("content", "")
                                    if content:
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                            except json.JSONDecodeError:
                                logger.error(f"Error decoding JSON: {line}")
                                # Skip this line instead of failing
                                continue
        return StreamingResponse(streaming_response(), media_type="text/event-stream")
    except Exception as e:
        logger.error(f"Error in perform_rag_query_stream: {e}", exc_info=True)
        return StreamingResponse(content=f"data: {json.dumps({'error': str(e)})}\n\ndata: {json.dumps({'done': True})}\n\n", media_type="text/event-stream")

# Similarly update the non-streaming function
def perform_rag_query(
    query: str,
    base_collection_name: str,
    user_collection_name: Optional[str], 
    qdrant_url: str,
    qdrant_api_key: Optional[str],
    openai_api_key: Optional[str],
    history: List[Dict[str, str]] = None,
    memory: List[Dict[str, str]] = None,
    model: str = "gpt-4o-mini",
    use_hybrid_search: bool = False,
    system_prompt: Optional[str] = None  # Add system prompt parameter
) -> str:
    # Process memory to enhance context
    memory_context = ""
    if memory and len(memory) > 0:
        # Format recent memory items (limited to last 10 to avoid token bloat)
        recent_memory = memory[-10:] if len(memory) > 10 else memory
        memory_context = "Previous conversation context:\n"
        for i, msg in enumerate(recent_memory):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            memory_context += f"[{role}]: {content}\n"
        memory_context += "\n"
    
    try:
        # Get documents from both collections if they exist
        base_docs = []
        try:
            base_docs = retrieve_documents(
                query=query,
                qdrant_url=qdrant_url,
                qdrant_api_key=qdrant_api_key,
                collection_name=base_collection_name,
                openai_api_key=openai_api_key,
                top_k=3,
                prefix="Knowledge Base",
                use_hybrid_search=use_hybrid_search
            )
        except Exception as e:
            logger.warning(f"Error retrieving from base collection: {str(e)}")
        
        user_docs = []
        if user_collection_name:
            try:
                user_docs = retrieve_documents(
                    query=query,
                    qdrant_url=qdrant_url,
                    qdrant_api_key=qdrant_api_key,
                    collection_name=user_collection_name,
                    openai_api_key=openai_api_key,
                    top_k=3,
                    prefix="User Uploaded",
                    use_hybrid_search=use_hybrid_search
                )
            except Exception as e:
                logger.warning(f"Error retrieving from user collection: {str(e)}")
        
        # Combine docs, prioritizing user docs
        all_docs = user_docs + base_docs
        
        # Prepare context from retrieved documents
        context = ""
        if all_docs:
            context = "Relevant information:\n\n"
            for i, doc in enumerate(all_docs[:6]): # Limit to avoid token issues
                source = doc.metadata.get("source", "Unknown")
                page = doc.metadata.get("page", "")
                page_info = f", page {page}" if page else ""
                context += f"[Document {i+1} - {source}{page_info}]\n{doc.page_content}\n\n"
        
        # Use system prompt from frontend if available, otherwise use a generic one
        if system_prompt:
            system_message = system_prompt
        else:
            # Adjust system message based on context available
            if all_docs:
                system_message = f"""You are a helpful assistant answering questions based on the provided documents.
Use the information from the documents to provide accurate and helpful responses.
If the documents don't contain relevant information to answer the question, say so and provide your best general knowledge answer.
{memory_context}"""
            else:
                system_message = f"""You are a helpful assistant answering questions based on your knowledge.
The user may have expected you to have access to specific documents, but they couldn't be retrieved or don't exist.
Please answer based on your general knowledge and be transparent about not having access to specific documents if relevant.
{memory_context}"""
        
        # Update the system message to include memory context
        system_message = f"""{system_message}
        
        {memory_context}
        
        Respond to the user's query based on the following relevant information:
        {context}
        
        Answer the user's question based on the provided context."""
        
        # Call language model with faster parameters
        from openai import OpenAI
        client = OpenAI(api_key=openai_api_key)
        
        # Format the conversation history
        messages = [{"role": "system", "content": system_message}]
        
        # Add history
        for msg in history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # Add current message
        messages.append({"role": "user", "content": query})
        
        # Generate response with reduced tokens for speed
        response = client.chat.completions.create(
            model=model,  # Use the model specified by the caller
            messages=messages,
            temperature=0.7,
            max_tokens=600,  # Reduced from 800 to 600
            presence_penalty=0.6,  # Added to encourage more focused responses
            frequency_penalty=0.2   # Added to prevent repetition
        )
        
        answer = response.choices[0].message.content
        logger.info("RAG query completed successfully")
        return answer
        
    except Exception as e:
        logger.error(f"Error in RAG query: {e}", exc_info=True)
        return f"I encountered an error processing your question. Please try again with a more specific query."

# --- How to Use (Instructions incorporated in comments and example) ---

if __name__ == '__main__':

    print("--- KB Indexer Example ---")

    # --- 1. Prerequisites ---
    #    - Python 3.8+ installed
    #    - Access to a Qdrant instance (local or cloud)
    #    - An OpenAI API Key

    # --- 2. Installation ---
    #    Run in your terminal:
    #    pip install qdrant-client "langchain>=0.1.0" langchain-community langchain-text-splitters langchain-openai openai tiktoken pdfplumber python-docx requests fastembed

    # --- 3. Environment Variables ---
    #    Set your OpenAI API Key. It's recommended to use environment variables for secrets.
    #    Linux/macOS: export OPENAI_API_KEY='your-openai-api-key'
    #    Windows (cmd): set OPENAI_API_KEY=your-openai-api-key
    #    Windows (PowerShell): $env:OPENAI_API_KEY='your-openai-api-key'
    #    Alternatively, you can pass the key directly to the KB_indexer function via the `openai_api_key` argument,
    #    but using environment variables is generally more secure.

    # --- 4. Configuration ---
    # Replace these placeholders with your actual values

    # Qdrant Configuration
    QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333") # Your Qdrant instance URL
    QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY", None) # Your Qdrant API Key (if using Qdrant Cloud or authentication)

    # File URLs to index (replace with URLs accessible by the script)
    # Ensure these are direct links to PDF, DOCX, or TXT files.
    FILE_URLS = [
        "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf", # Example PDF
        "https://www.unm.edu/~unmvclib/powerpoint/pptexamples/sample.docx", # Example DOCX (check if link works)
        "https://raw.githubusercontent.com/google/gemini-api/main/README.md", # Example TXT/MD (parsed as TXT)
        "https://invalid-url-that-will-fail.xyz/document.pdf" # Example of a failing URL
    ]

    # Collection Name Construction (example based on prompt)
    USER_EMAIL = "test@example.com"
    GPT_NAME = "my_openai_rag_gpt"
    # Sanitize email and GPT name to create a valid collection name
    # Qdrant collection names must start with a letter and contain only letters, numbers, and underscores.
    sanitized_email = ''.join(c if c.isalnum() else '_' for c in USER_EMAIL)
    sanitized_gpt_name = ''.join(c if c.isalnum() else '_' for c in GPT_NAME)
    # Ensure it starts with a letter if the sanitized email doesn't
    collection_prefix = "kb" if not sanitized_email or not sanitized_email[0].isalpha() else ""
    dynamic_collection_name = f"{collection_prefix}_{sanitized_email}_{sanitized_gpt_name}"
    # Ensure name is not excessively long if needed
    dynamic_collection_name = dynamic_collection_name[:63] # Example length limit if necessary

    # --- 5. Running the Indexer ---
    print(f"Target Qdrant URL: {QDRANT_URL}")
    print(f"Target Collection Name: {dynamic_collection_name}")
    print(f"Number of files to process: {len(FILE_URLS)}")

    # Check if OpenAI API key is available (optional check, the function handles it)
    openai_key_present = bool(os.environ.get("OPENAI_API_KEY"))
    if not openai_key_present:
         print("\nWARNING: OPENAI_API_KEY environment variable not found. Make sure it's set.")
         # You could add logic here to prompt for the key or read from a config file if needed
    else:
        print("OpenAI API key found in environment.")

    # Execute the main function
    # Set force_recreate_collection=True ONLY if you want to clear the collection first.
    # Set force_recreate_collection=False to append/update documents.
    # Set use_hybrid_search=True to enable hybrid search with sparse embeddings
    success = KB_indexer(
        file_urls=FILE_URLS,
        qdrant_url=QDRANT_URL,
        qdrant_api_key=QDRANT_API_KEY,
        collection_name=dynamic_collection_name,
        openai_api_key=None, # Set to your key string if not using env var, e.g., "sk-..."
        force_recreate_collection=True, # Be careful with True in production!
        max_workers=5, # Adjust based on your machine/network
        use_hybrid_search=True, # Enable hybrid search capability
        system_prompt="This is a system prompt",
        schema={"model": "gpt-4o-mini"}
    )

    # --- 6. Result ---
    if success:
        print(f"\n--- KB Indexer finished successfully for collection '{dynamic_collection_name}' ---")
        
        # Example query using hybrid search
        print("\n--- Testing hybrid search query ---")
        try:
            result = perform_rag_query(
                query="What does this document talk about?",
                base_collection_name=dynamic_collection_name,
                user_collection_name=None,
                qdrant_url=QDRANT_URL,
                qdrant_api_key=QDRANT_API_KEY,
                openai_api_key=None,
                use_hybrid_search=True
            )
            print(f"Query result: {result}")
        except Exception as e:
            print(f"Error testing query: {e}")
    else:
        print(f"\n--- KB Indexer failed for collection '{dynamic_collection_name}'. Check 'kb_indexer.log' for details. ---")