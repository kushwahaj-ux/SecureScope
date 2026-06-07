from dotenv import load_dotenv
load_dotenv()
import requests
import time
import os


class CVELookup:

    def __init__(self, api_key=None):
        self.base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        if self.api_key:
            print("CVE Lookup Ready! (With API key — fast mode)")
        else:
            print("CVE Lookup Ready! (No API key — rate limited)")

    SERVICE_MAP = {
        "ssh":      "OpenSSH",
        "http":     "Apache HTTP Server",
        "https":    "Apache HTTP Server",
        "smtp":     "Postfix",
        "ftp":      "vsftpd",
        "mysql":    "MySQL",
        "mariadb":  "MariaDB",
        "postgres": "PostgreSQL",
        "rdp":      "Remote Desktop",
        "smb":      "Samba",
        "imap":     "Dovecot",
        "pop3":     "Dovecot",
        "dns":      "BIND",
        "rpc":      "rpcbind",
        "redis":    "Redis",
        "mongodb":  "MongoDB",
        "nginx":    "nginx",
        "apache":   "Apache HTTP Server",
        "iis":      "Internet Information Services",
        "tomcat":   "Apache Tomcat",
        "domain":   "BIND DNS",
        "rpcbind":  "rpcbind",
    }

    def _build_query(self, service, version):
        service_lower = service.lower().strip()
        product = service
        for key, val in self.SERVICE_MAP.items():
            if key in service_lower:
                product = val
                break
        if version and version.strip():
            return f"{product} {version.strip()}"
        return product

    def _extract_score(self, metrics):
        # Try v3.1 and v3.0 first
        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_key in metrics:
                try:
                    data = metrics[metric_key][0]
                    cvss = data.get("cvssData", {})
                    score = cvss.get("baseScore", 0)
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    return float(score), severity.upper()
                except (IndexError, KeyError, TypeError):
                    continue

        # Fallback to v2
        if "cvssMetricV2" in metrics:
            try:
                data = metrics["cvssMetricV2"][0]
                cvss = data.get("cvssData", {})
                score = cvss.get("baseScore", 0)
                severity = data.get("baseSeverity", "UNKNOWN")
                if severity == "UNKNOWN" and score >= 7.0:
                    severity = "HIGH"
                elif severity == "UNKNOWN" and score >= 4.0:
                    severity = "MEDIUM"
                elif severity == "UNKNOWN":
                    severity = "LOW"
                return float(score), severity.upper()
            except (IndexError, KeyError, TypeError):
                pass

        return 0.0, "UNKNOWN"

    def _fetch_cves(self, query, headers, max_results):
        params = {
            "keywordSearch": query,
            "resultsPerPage": max_results
           
        }
        delay = 0.6 if self.api_key else 6.0
        time.sleep(delay)

        resp = requests.get(
            self.base,
            params=params,
            headers=headers,
            timeout=15
        )

        if resp.status_code == 403:
            print("[CVE] Rate limited by NVD — sleeping 30s...")
            time.sleep(30)
            resp = requests.get(
                self.base,
                params=params,
                headers=headers,
                timeout=15
            )

        if resp.status_code != 200:
            print(f"[CVE] NVD returned {resp.status_code}")
            return []

        vulnerabilities = resp.json().get("vulnerabilities", [])
        print(f"[CVE] Found {len(vulnerabilities)} CVEs for '{query}'")
        return vulnerabilities

    def search(self, service, version="", max_results=5):
        if not service or service.lower() in [
            "unknown", "", "tcpwrapped", "filtered"
        ]:
            return []

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        query = self._build_query(service, version)
        print(f"[CVE] Searching: '{query}'")

        try:
            vulnerabilities = self._fetch_cves(query, headers, max_results)

            # Fallback without version if no results
            if len(vulnerabilities) == 0 and version and version.strip():
                print(f"[CVE] No results with version — retrying without...")
                query_no_version = self._build_query(service, "")
                vulnerabilities = self._fetch_cves(
                    query_no_version, headers, max_results
                )

            cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                metrics = cve_data.get("metrics", {})
                score, severity = self._extract_score(metrics)

                # Skip low scores
                if score < 4.0:
                    continue

                # Skip unknown severity
                if severity == "UNKNOWN":
                    continue

                # Skip very old CVEs
                cve_id = cve_data.get("id", "CVE-0000-0000")
                try:
                    cve_year = int(cve_id.split("-")[1])
                    if cve_year < 2015:
                        continue
                except (IndexError, ValueError):
                    pass

                # Get English description
                descriptions = cve_data.get("descriptions", [])
                desc = "No description available"
                for d in descriptions:
                    if d.get("lang", "") == "en" or d.get("language", "") == "en":
                        val = d.get("value", "").strip()
                        if val and val != "** RESERVED **":
                            desc = val
                            break

                cves.append({
                    "id": cve_id,
                    "score": score,
                    "severity": severity,
                    "desc": desc[:250],
                    "service": service,
                    "version": version
                })

            cves = sorted(cves, key=lambda x: x["score"], reverse=True)

            if cves:
                print(f"[CVE] ✅ {len(cves)} valid CVEs after filtering")
            else:
                print(f"[CVE] ⚠️ No CVEs above threshold for '{service}'")

            return cves

        except requests.exceptions.Timeout:
            print(f"[CVE] Timeout searching '{query}'")
            return []
        except Exception as e:
            print(f"[CVE] Error: {e}")
            return []


if __name__ == "__main__":
    cve = CVELookup()
    tests = [
        ("ssh",     "8.0"),
        ("http",    ""),
        ("mysql",   "5.7"),
        ("nginx",   "1.24.0"),
        ("smtp",    "4.99.4"),
        ("imap",    ""),
        ("pop3",    ""),
        ("rpcbind", "2-4"),
    ]
    for service, version in tests:
        print(f"\n--- {service} {version} ---")
        results = cve.search(service, version)
        for r in results:
            print(f"  {r['id']} | Score: {r['score']} | {r['severity']}")
            print(f"  {r['desc'][:80]}...")
        if not results:
            print("  No CVEs found")
        print()