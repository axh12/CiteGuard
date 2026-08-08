import json
from rank_bm25 import BM25Okapi

with open("data/raw/cves.json", "r") as f:
    cve_records = json.load(f)

descriptions = [record.get("description", "") for record in cve_records]
desc = list(descriptions)
tokenized_descriptions = [desc.lower().split() for desc in descriptions]
bm25 = BM25Okapi(tokenized_descriptions)

query = "SQL injection vulnerability in web application"
query_tokens = query.lower().split()
top_results = bm25.get_top_n(query_tokens, descriptions, n=5)
for result in top_results:
    print(result)