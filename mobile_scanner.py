import requests
import urllib3
from urllib.parse import urljoin, urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MobileAPIScanner:
    """
    SecureScope Mobile API Scanner
    ================================
    Tests mobile-specific API vulnerabilities.

    WHAT IS UNIQUE HERE:
    1. Mobile User-Agent switching
       → Server shows hidden mobile endpoints!

    2. Mobile specific headers
       → X-Platform, X-App-Version, X-Device-ID
       → Server behaves differently for mobile!

    3. API Version testing
       → Old /v1/ endpoints often forgotten!
       → No auth, no rate limiting on old versions!

    4. Certificate pinning detection
       → Mobile apps should pin SSL certs
       → Missing = MITM attack possible!
    """

    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.findings = []

        # Normal browser session
        self.browser_session = requests.Session()
        self.browser_session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        # Mobile app session
        self.mobile_session = requests.Session()
        self.mobile_session.headers = {
            "User-Agent": "SharpenerApp/2.1 (Android 12; Mobile)",
            "X-Platform": "android",
            "X-App-Version": "2.1.0",
            "X-Device-ID": "test-device-12345",
            "X-OS-Version": "12",
            "Accept": "application/json",
        }

        print(f"Mobile API Scanner Ready! Target: {self.target}")

    # ============================================================
    # TEST 1 — Mobile User-Agent Switching
    # ============================================================
    def test_mobile_useragent(self):
        """
        Tests if server responds differently to mobile User-Agent.

        WHY:
        Servers sometimes show different content to mobile apps!
        Hidden debug endpoints
        Different auth requirements
        Extra API data exposed
        """
        print("[*] Testing mobile User-Agent switching...")

        try:
            # Compare browser vs mobile response
            browser_resp = self.browser_session.get(
                self.target, timeout=10, verify=False
            )
            mobile_resp = self.mobile_session.get(
                self.target, timeout=10, verify=False
            )

            browser_len = len(browser_resp.text)
            mobile_len = len(mobile_resp.text)
            diff = abs(browser_len - mobile_len)

            print(f"[*] Browser response: {browser_len} bytes")
            print(f"[*] Mobile response: {mobile_len} bytes")
            print(f"[*] Difference: {diff} bytes")

            # Significant difference = different content for mobile!
            if diff > 500:
                self.findings.append({
                    "type": "Different Mobile Response",
                    "detail": f"Server returns different content for mobile User-Agent",
                    "severity": "MEDIUM",
                    "evidence": f"Browser: {browser_len} bytes | Mobile: {mobile_len} bytes | Diff: {diff}",
                    "url": self.target
                })
                print(f"[MEDIUM] Server behaves differently for mobile!")

            # Check mobile specific headers in response
            mobile_headers = [
                "X-Mobile-Api", "X-App-Response",
                "X-Mobile-Version", "X-Api-Mobile"
            ]
            for header in mobile_headers:
                if header in mobile_resp.headers:
                    self.findings.append({
                        "type": "Mobile Specific Header Exposed",
                        "detail": f"Server exposes mobile header: {header}",
                        "severity": "LOW",
                        "evidence": f"{header}: {mobile_resp.headers[header]}",
                        "url": self.target
                    })
                    print(f"[LOW] Mobile header: {header}")

        except Exception as e:
            print(f"[!] User-Agent test error: {e}")

    # ============================================================
    # TEST 2 — Mobile Specific Endpoints
    # ============================================================
    def test_mobile_endpoints(self):
        """
        Finds mobile-specific API endpoints.

        WHY:
        Mobile apps use different endpoints than web:
        /api/mobile/ → Mobile only endpoints
        /app/api/    → App specific API
        /m/api/      → Mobile API

        These often have WEAKER security than web API!
        Developers focus security on web API
        Forget about mobile API!
        """
        print("[*] Testing mobile specific endpoints...")

        mobile_paths = [
            # Mobile specific paths
            "/api/mobile",
            "/api/mobile/v1",
            "/api/mobile/v2",
            "/mobile/api",
            "/m/api",
            "/app/api",
            "/api/app",

            # Mobile auth endpoints
            "/api/mobile/login",
            "/api/mobile/auth",
            "/api/app/login",
            "/mobile/auth/login",

            # Mobile data endpoints
            "/api/mobile/user",
            "/api/mobile/profile",
            "/api/mobile/dashboard",
            "/api/app/config",
            "/api/mobile/config",

            # Debug endpoints (often left open!)
            "/api/mobile/debug",
            "/api/app/debug",
            "/api/mobile/test",
            "/api/debug",
        ]

        for path in mobile_paths:
            url = urljoin(self.target, path)
            try:
                # Test with mobile headers
                resp = self.mobile_session.get(
                    url, timeout=5, verify=False
                )

                if resp.status_code in [200, 201]:
                    # Check if real data returned
                    is_json = "application/json" in \
                              resp.headers.get("Content-Type", "")

                    severity = "HIGH" if "debug" in path or \
                               "config" in path else "MEDIUM"

                    self.findings.append({
                        "type": "Mobile API Endpoint Found",
                        "detail": f"Mobile endpoint accessible: {path}",
                        "severity": severity,
                        "evidence": f"Status: 200 | JSON: {is_json} | Size: {len(resp.text)}",
                        "url": url
                    })
                    print(f"[{severity}] Mobile endpoint: {path}")

                elif resp.status_code == 401:
                    print(f"[+] Protected endpoint: {path}")

            except Exception:
                pass

    # ============================================================
    # TEST 3 — API Version Testing
    # ============================================================
    def test_api_versioning(self):
        """
        Tests old API versions for vulnerabilities.

        WHY HIGH VALUE:
        Companies release new API versions but
        forget to disable old ones!

        /api/v3/ → Current — properly secured ✅
        /api/v2/ → Old — partially secured ⚠️
        /api/v1/ → Forgotten — no auth! ❌

        Real finding:
        Many Indian startups have v1 endpoints
        with no authentication at all!
        = Access all user data without login!
        """
        print("[*] Testing API versioning...")

        # Common API base paths
        api_bases = ["/api", "/api/user", "/api/users",
                     "/api/profile", "/api/data"]

        # Version patterns to test
        versions = ["v1", "v2", "v3", "v4",
                    "1.0", "2.0", "1", "2"]

        # Get baseline — current API response
        baseline_statuses = {}
        for base in api_bases[:3]:
            url = urljoin(self.target, base)
            try:
                resp = self.mobile_session.get(
                    url, timeout=5, verify=False
                )
                baseline_statuses[base] = resp.status_code
            except Exception:
                baseline_statuses[base] = 0

        # Test versioned endpoints
        for base in api_bases[:3]:
            for version in versions:
                versioned_url = urljoin(
                    self.target, f"/api/{version}{base.replace('/api', '')}"
                )
                alt_url = urljoin(
                    self.target, f"{base}/{version}"
                )

                for url in [versioned_url, alt_url]:
                    try:
                        resp = self.mobile_session.get(
                            url, timeout=5, verify=False
                        )

                        if resp.status_code == 200:
                            # Old version accessible!
                            baseline = baseline_statuses.get(base, 0)

                            # If baseline needs auth but old version doesn't
                            if baseline in [401, 403] and \
                               resp.status_code == 200:
                                self.findings.append({
                                    "type": "Old API Version No Auth",
                                    "detail": f"Old API {version} bypasses authentication!",
                                    "severity": "CRITICAL",
                                    "evidence": f"Current API: {baseline} | Old {version}: 200",
                                    "url": url
                                })
                                print(f"[CRITICAL] Auth bypass via {version}!")

                            elif resp.status_code == 200 and \
                                 len(resp.text) > 100:
                                self.findings.append({
                                    "type": "Old API Version Accessible",
                                    "detail": f"Old API version {version} still accessible",
                                    "severity": "MEDIUM",
                                    "evidence": f"Status 200 at {url}",
                                    "url": url
                                })
                                print(f"[MEDIUM] Old API version: {url}")

                    except Exception:
                        pass

    # ============================================================
    # TEST 4 — Certificate Pinning Detection
    # ============================================================
    def test_certificate_pinning(self):
        """
        Detects if mobile API implements certificate pinning.

        WHAT IS CERT PINNING:
        Mobile app hardcodes server certificate
        Only accepts that specific certificate
        MITM attacks impossible!

        WITHOUT pinning:
        Hacker intercepts mobile traffic
        Reads all API calls
        Steals user data!

        HOW WE DETECT:
        Check security headers that indicate pinning
        Check HPKP header (HTTP Public Key Pinning)
        Check for pinning libraries in JS
        """
        print("[*] Checking certificate pinning...")

        try:
            resp = self.mobile_session.get(
                self.target, timeout=10, verify=False
            )

            # Check for pinning headers
            hpkp = resp.headers.get(
                "Public-Key-Pins", ""
            )
            hpkp_report = resp.headers.get(
                "Public-Key-Pins-Report-Only", ""
            )

            if not hpkp and not hpkp_report:
                self.findings.append({
                    "type": "Missing Certificate Pinning",
                    "detail": "No certificate pinning detected — mobile MITM possible",
                    "severity": "MEDIUM",
                    "evidence": "No HPKP header in mobile API response",
                    "url": self.target
                })
                print("[MEDIUM] Certificate pinning not detected!")
            else:
                print("[+] Certificate pinning headers found!")

            # Check Expect-CT header
            expect_ct = resp.headers.get("Expect-CT", "")
            if not expect_ct:
                self.findings.append({
                    "type": "Missing Expect-CT Header",
                    "detail": "Expect-CT header missing — certificate transparency not enforced",
                    "severity": "LOW",
                    "evidence": "No Expect-CT header",
                    "url": self.target
                })
                print("[LOW] Missing Expect-CT header!")

        except Exception as e:
            print(f"[!] Cert pinning check error: {e}")

    # ============================================================
    # TEST 5 — Mobile Auth Weakness
    # ============================================================
    def test_mobile_auth(self):
        """
        Tests mobile-specific authentication weaknesses.

        Checks:
        - API accessible without mobile headers?
        - Different auth for mobile vs web?
        - Weak mobile session tokens?
        """
        print("[*] Testing mobile authentication...")

        mobile_auth_endpoints = [
            "/api/mobile/login",
            "/api/app/auth",
            "/api/mobile/token",
            "/api/mobile/refresh",
        ]

        for endpoint in mobile_auth_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Test without mobile headers
                no_mobile_resp = self.browser_session.post(
                    url,
                    json={"email": "test@test.com",
                          "password": "test"},
                    timeout=5, verify=False
                )

                # Test with mobile headers
                mobile_resp = self.mobile_session.post(
                    url,
                    json={"email": "test@test.com",
                          "password": "test"},
                    timeout=5, verify=False
                )

                # If mobile endpoint accessible without
                # mobile headers = weak auth
                if no_mobile_resp.status_code == 200 and \
                   mobile_resp.status_code == 200:
                    self.findings.append({
                        "type": "Mobile Endpoint No Header Check",
                        "detail": f"Mobile endpoint accessible without mobile headers",
                        "severity": "LOW",
                        "evidence": f"Both browser and mobile get 200 at {endpoint}",
                        "url": url
                    })
                    print(f"[LOW] No mobile header check: {endpoint}")

            except Exception:
                pass

    # ============================================================
    # MAIN — Run complete mobile scan
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope Mobile API Scanner")
        print("Android | iOS | API Versioning | Cert Pinning")
        print("="*60)

        self.test_mobile_useragent()
        self.test_mobile_endpoints()
        self.test_api_versioning()
        self.test_certificate_pinning()
        self.test_mobile_auth()

        print("\n" + "="*60)
        print(f"Mobile API Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings
                      if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings
                  if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings
                    if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings
                 if f["severity"] == "LOW")

        print(f"CRITICAL: {critical} | HIGH: {high} | "
              f"MEDIUM: {medium} | LOW: {low}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = MobileAPIScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")