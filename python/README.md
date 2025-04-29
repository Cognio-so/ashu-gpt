# AI Agent with Hybrid Search

This project implements an AI agent backend with a hybrid search retrieval mechanism for improved results in RAG (Retrieval Augmented Generation) applications.

## Hybrid Search Implementation

This implementation combines vector-based semantic search with BM25 keyword-based search to improve retrieval quality:

- **Vector Search**: Uses OpenAI embeddings to find semantically similar content
- **BM25 Search**: Uses keyword matching to find lexically similar content
- **Ensemble Retriever**: Combines both approaches with customizable weights

### Benefits of Hybrid Search

- Better handling of both semantic and keyword-based queries
- Improved recall for domain-specific terminology
- Reduced "hallucination" due to more accurate retrieval
- More robust to different query formulations

### Configuration Parameters

The hybrid search can be configured with:

- `use_hybrid`: Boolean flag to enable/disable hybrid search (default: `true`)
- `weight_sparse`: Weight of BM25 search in the ensemble (0-1, default: `0.3`)

## API Usage

When making chat requests to the API, you can control the hybrid search behavior:

```json
{
  "message": "Your question here",
  "collection_name": "your_collection",
  "use_hybrid": true,
  "weight_sparse": 0.3
}
```

## Dependencies

- langchain, langchain-openai, langchain-qdrant: Core RAG components
- qdrant-client: Vector database
- fastapi: API framework
- Various document parsers (PDF, DOCX, TXT)

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables (see .env.example)
3. Run the server: `uvicorn main:app --reload` 
No newline at end of file
