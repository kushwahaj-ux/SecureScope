import requests
import time

class CVELookup:
    def __init__(self, api_key=None):
        self.base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        print("CVE Lookup Ready!")

    def search(self, service, version="", max_results=5):
        query = f"{service} {version}".strip()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {
            "keywordSearch": query,
            "resultsPerPage": max_results
        }
        try:
            time.sleep(0.6)
            resp = requests.get(self.base, params=params,
                               headers=headers, timeout=15)
            cves = []
            for vuln in resp.json().get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                m = cve_data.get("metrics", {})
                score, sev = 0, "UNKNOWN"
                if "cvssMetricV31" in m:
                    d = m["cvssMetricV31"][0]["cvssData"]
                    score = d.get("baseScore", 0)
                    sev = d.get("baseSeverity", "?")
                desc = next(
                    (d.get("value", "") for d in cve_data.get("descriptions", [])
                     if d.get("language") == "en"), ""
                )
                cves.append({
                    "id": cve_data.get("id"),
                    "score": score,
                    "severity": sev,
                    "desc": desc[:250]
                })
            return sorted(cves, key=lambda x: x["score"], reverse=True)
        except Exception as e:
            print(f"CVE error: {e}")
            return []

if __name__ == "__main__":
    cve = CVELookup()
    results = cve.search("Apache", "2.4.49")
    for r in results:
        print(f"{r['id']} | Score: {r['score']} | {r['severity']}")