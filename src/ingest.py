import requests

url="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
response=requests.get(url)
if response.status_code == 200:
    data=response.json()
    print(data) 

for vuln in data["vulnerabilities"]:
    cvn_id=vuln["cve"]["id"]
    for desc in vuln["cve"]["descriptions"]:
        if desc["lang"]=="en":
            print("ID=",cvn_id,"Description=",desc["value"])