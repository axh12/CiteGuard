import json
import chromadb

from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")

with open("data/raw/cves.json", "r") as f:
    cve_records = json.load(f)

descriptions = []
for record in cve_records:
    descriptions.append(record["description"])
model_embeddings = model.encode(descriptions)
print(f"Total embeddings generated: {len(model_embeddings)}")
print(f"Embedding dimension: {len(model_embeddings[0])}")

client = chromadb.PersistentClient(path="data/chroma_db")
collection = client.get_or_create_collection(name="cve_records")
collection.add(
    documents=descriptions,
    embeddings=model_embeddings,
    ids=[record["id"] for record in cve_records],
    metadatas=[{"baseScore": record["baseScore"] if record["baseScore"] is not None else 0} for record in cve_records]
)

query = "SQL injection vulnerability in web application"
query_embedding = model.encode([query])

results = collection.query(
    query_embeddings=query_embedding,
    n_results=5
)

print(results)