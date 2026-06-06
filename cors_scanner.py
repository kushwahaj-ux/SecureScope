import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class CORSScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        print(f"CORS Scanner Ready! Target: {self.target}")

    def check_wildcard_cors(self):
        """
        Checks if server allows ALL origins with credentials.
        WHY: Most dangerous CORS config — any website can
        steal user data using their own cookies!
        """
        print("[*] Checking wildcard CORS...")
        try:
            resp = self.session.get(
                self.target,
                headers={"Origin": "https://evil-test.com"},
                timeout=10,
                verify=False
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                self.findings.append({
                    "type": "CORS Wildcard with Credentials",
                    "detail": "Server allows ALL origins with credentials — critical misconfiguration",
                    "severity": "CRITICAL",
                    "evidence": f"Allow-Origin: {acao} | Allow-Credentials: {acac}",
                    "url": self.target
                })
                print("[CRITICAL] Wildcard CORS with credentials!")

            elif acao == "*":
                self.findings.append({
                    "type": "CORS Wildcard",
                    "detail": "Server allows requests from any origin",
                    "severity": "MEDIUM",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "url": self.target
                })
                print("[MEDIUM] Wildcard CORS found!")

        except Exception as e:
            print(f"[!] Wildcard check error: {e}")    

    def check_origin_reflection(self):
        """
        Checks if server blindly copies Origin header back.
        WHY: Server should only allow SPECIFIC trusted origins.
        If it reflects ANY origin = attacker sends their domain
        = gets full access to API with user credentials!
        Real example: Many Indian startups have this issue.
        """
        print("[*] Checking origin reflection...")
        
        test_origins = [
            "https://evil-test-securescope.com",
            "https://attacker.com",
            "null"
        ]
        
        for origin in test_origins:
            try:
                resp = self.session.get(
                    self.target,
                    headers={"Origin": origin},
                    timeout=10,
                    verify=False
                )
                
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                
                # Server reflected our evil origin back!
                if acao == origin:
                    severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                    self.findings.append({
                        "type": "CORS Origin Reflection",
                        "detail": f"Server reflects attacker origin: {origin}",
                        "severity": severity,
                        "evidence": f"Sent: {origin} | Received: {acao} | Credentials: {acac}",
                        "url": self.target
                    })
                    print(f"[{severity}] Origin reflection: {origin}")

            except Exception:
                pass

    def check_null_origin(self):
        """
        Checks if server accepts null origin.
        WHY: Attackers use sandboxed iframes to send
        null origin — bypasses all origin restrictions!
        """
        print("[*] Checking null origin...")
        try:
            resp = self.session.get(
                self.target,
                headers={"Origin": "null"},
                timeout=10,
                verify=False
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "null":
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self.findings.append({
                    "type": "CORS Null Origin Allowed",
                    "detail": "Server accepts null origin — sandboxed iframe attack possible",
                    "severity": severity,
                    "evidence": f"Allow-Origin: {acao} | Credentials: {acac}",
                    "url": self.target
                })
                print(f"[{severity}] Null origin accepted!")
            else:
                print("[+] Null origin rejected — good!")

        except Exception as e:
            print(f"[!] Null origin check error: {e}")

    def check_cors_on_api_endpoints(self):
        """
        Tests CORS on common API endpoints.
        WHY: Main page might be secure but API endpoints
        often have misconfigured CORS — developers forget!
        """
        print("[*] Checking CORS on API endpoints...")

        api_paths = [
            "/api", "/api/v1", "/api/v2",
            "/api/user", "/api/users",
            "/api/auth", "/api/login",
            "/api/data", "/api/admin",
            "/graphql", "/rest"
        ]

        for path in api_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                resp = self.session.get(
                    url,
                    headers={"Origin": "https://evil-test-securescope.com"},
                    timeout=5,
                    verify=False
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "https://evil-test-securescope.com":
                    severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                    self.findings.append({
                        "type": "CORS API Endpoint Misconfiguration",
                        "detail": f"API endpoint reflects attacker origin at {path}",
                        "severity": severity,
                        "evidence": f"Path: {path} | Origin reflected: {acao}",
                        "url": url
                    })
                    print(f"[{severity}] CORS misconfiguration at: {path}")

            except Exception:
                pass

    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope CORS Scanner")
        print("="*60)

        self.check_wildcard_cors()
        self.check_origin_reflection()
        self.check_null_origin()
        self.check_cors_on_api_endpoints()

        print("\n" + "="*60)
        print(f"CORS Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = CORSScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")                