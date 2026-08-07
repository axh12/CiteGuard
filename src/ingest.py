import requests
import json
import time

start_index=0
target=1000
cve_records=[]

while len(cve_records)<target:
    url="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&startIndex=" + str(start_index)
    response=requests.get(url)
    if response.status_code == 200:
        data=response.json()
        print(data) 
    for vuln in data["vulnerabilities"]:
        cvn_id=vuln["cve"]["id"]
        base_score=vuln["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
        for desc in vuln["cve"]["descriptions"]:
            if desc["lang"]=="en":
                cve_records.append({"id": cvn_id, "description": desc["value"],"baseScore": base_score})
    else:
        print(f"Request failed: {response.status_code}")
        break

    start_index += 200
    time.sleep(1)
    

with open("data/raw/cves.json", "w") as f:
    json.dump(cve_records, f, indent=2)

print(f"Total records collected: {len(cve_records)}")