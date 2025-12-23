# instructions for agents.md: Chroma DB Integration

## 🤖 Role and Context
You are an agent equipped with **Long-Term Memory** capabilities via the Chroma Model Context Protocol (MCP) server. You use Chroma to store, retrieve, and manage unstructured information as vector embeddings, allowing you to "remember" context across sessions and search through large datasets efficiently.

- **Chroma Core:** [https://github.com/chroma-core/chroma](https://github.com/chroma-core/chroma)
- **Chroma MCP Server:** [https://github.com/chroma-core/chroma-mcp](https://github.com/chroma-core/chroma-mcp)

---

## 🛠 Available Toolset
The following tools are available via the Chroma MCP. You should invoke these when you need to store facts, retrieve documentation, or maintain a persistent knowledge base for the user.

1.  **`create_collection`**: Initialize a new storage bucket (collection).
2.  **`list_collections`**: See all existing memory buckets.
3.  **`add_documents`**: Store text snippets with automatic embedding generation.
4.  **`query_collection`**: Search for the most semantically relevant information based on a natural language string.
5.  **`delete_collection`**: Wipe a specific memory bucket.
6.  **`get_collection`**: Get metadata about a collection.

---

## 🧠 Strategic Guidelines

### 1. When to Use Memory
- **Storing:** When the user provides information that will be relevant in the future (API keys [if safe], architectural decisions, project goals, personal preferences).
- **Retrieving:** When a user asks a question about the project history, "how things work," or asks to find a needle in a haystack of past conversations.

### 2. Collection Management
- **Naming Convention:** Use lowercase, alphanumeric names with underscores (e.g., `project_documentation`, `user_preferences`, `coding_snippets`).
- **Contextual Isolation:** Create different collections for distinct topics to avoid cross-contamination of search results.

### 3. Effective Querying
- Instead of searching for keywords, search for **concepts**.
- **Bad Query:** "Search for the file created on Tuesday."
- **Good Query:** "Architectural patterns used for the authentication module."

### 4. Upserting Data (Adding/Updating)
- Always include **metadata** if possible (e.g., source file, timestamp, or category) to help filter results later.
- Chunk large documents before adding them to ensure each entry is focused and within token limits for vectorization.
-
---

## 📝 Example Workflows

### Scenario A: Remembering Project Specs
1.  **User:** "We are building this project using FastAPI and using PostgreSQL for the DB."
2.  **Agent Action:** Call `add_documents` to the `project_context` collection.
3.  **Entry:** `{"documents": ["Backend: FastAPI, Database: PostgreSQL"], "metadatas": [{"category": "stack"}]}`

### Scenario B: Retrieving Instructions
1.  **User:** "How do we handle database migrations?"
2.  **Agent Action:** Call `query_collection` on `project_context` with the string "database migration instructions".
3.  **Agent Response:** Synthesize the results from Chroma into a helpful answer.

---

## ⚠️ Constraints
- **Security:** Do not store secrets or plaintext passwords in Chroma unless the instance is encrypted/secured.
- **Maintenance:** Periodically list collections to ensure the database isn't cluttered with "temp" collections.
- **Consistency:** Use consistent terminology when storing facts to improve retrieval accuracy.
