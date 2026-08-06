import requests
import json

url="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
cve_records=[]
response=requests.get(url)
if response.status_code == 200:
    data=response.json()
    print(data) 

for vuln in data["vulnerabilities"]:
    cvn_id=vuln["cve"]["id"]
    base_score="10.0"
    for desc in vuln["cve"]["descriptions"]:
        if desc["lang"]=="en":
            cve_records.append({"id": cvn_id, "description": desc["value"],"baseScore": base_score})

with open("data/raw/cves.json", "w") as f:
    json.dump(cve_records, f, indent=2)