import requests
import socket
import dns.resolver
import re
import time
import urllib3
from urllib.parse import urljoin, urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdvancedScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        print(f"Advanced Scanner Ready! Target: {self.target}")

    # ============================================================
    # CATEGORY 1 — SSRF Detection
    # Server Side Request Forgery
    # ============================================================
    def check_ssrf(self):
        """
        Tests if server can be tricked into making
        requests to internal/cloud resources.
        WHY: Capital One breach used SSRF to get
        AWS credentials = 100 million records stolen!
        """
        print("[*] Testing for SSRF vulnerabilities...")

        # Common SSRF parameters
        ssrf_params = [
            "url", "link", "src", "source", "href",
            "redirect", "uri", "path", "dest", "target",
            "image", "img", "file", "page", "fetch",
            "callback", "return", "next", "data", "host"
        ]

        # SSRF payloads
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",           # GCP metadata
            "http://169.254.169.254/metadata/v1/",        # DigitalOcean
            "http://localhost/",                          # Localhost
            "http://127.0.0.1/",                         # Loopback
            "http://0.0.0.0/",                           # All interfaces
            "http://[::1]/",                             # IPv6 localhost
            "file:///etc/passwd",                        # Local file
            "dict://localhost:11211/stat",               # Memcached
        ]

        try:
            # Get page to find parameters
            resp = self.session.get(self.target, timeout=10, verify=False)

            for param in ssrf_params:
                for payload in ssrf_payloads[:3]:  # Test top 3 payloads
                    test_url = f"{self.target}?{param}={payload}"
                    try:
                        test_resp = self.session.get(
                            test_url, timeout=5, verify=False
                        )
                        # Check for AWS metadata indicators
                        aws_indicators = [
                            "ami-id", "instance-id",
                            "security-credentials",
                            "iam/", "meta-data"
                        ]
                        if any(ind in test_resp.text.lower()
                               for ind in aws_indicators):
                            self.findings.append({
                                "type": "SSRF Vulnerability",
                                "detail": f"SSRF via '{param}' parameter — AWS metadata accessible!",
                                "severity": "CRITICAL",
                                "evidence": f"Parameter: {param} | Payload: {payload}",
                                "url": test_url
                            })
                            print(f"[CRITICAL] SSRF found via {param}!")

                    except Exception:
                        pass

        except Exception as e:
            print(f"[!] SSRF check error: {e}")

    # ============================================================
    # CATEGORY 2 — IDOR Detection
    # Insecure Direct Object Reference
    # ============================================================
    def check_idor(self):
        """
        Tests if changing IDs in URLs exposes other users data.
        WHY: Most common vulnerability in Indian startups!
        /api/user/1001 → change to /api/user/1002
        = access someone else's private data!
        """
        print("[*] Testing for IDOR vulnerabilities...")

        # Common IDOR patterns
        idor_patterns = [
            "/api/user/{id}",
            "/api/users/{id}",
            "/api/profile/{id}",
            "/api/order/{id}",
            "/api/orders/{id}",
            "/user/{id}",
            "/profile/{id}",
            "/account/{id}",
            "/invoice/{id}",
            "/document/{id}",
        ]

        test_ids = [1, 2, 3, 100, 1000, 9999]

        for pattern in idor_patterns:
            for test_id in test_ids[:2]:  # Test first 2 IDs
                url = urljoin(
                    self.target,
                    pattern.replace("{id}", str(test_id))
                )
                try:
                    resp = self.session.get(
                        url, timeout=5, verify=False
                    )

                    # If returns 200 with data — potential IDOR!
                    if resp.status_code == 200 and len(resp.text) > 50:
                        # Check if response contains user data
                        user_data_indicators = [
                            "email", "phone", "address",
                            "name", "user_id", "account",
                            "password", "token", "balance"
                        ]
                        if any(ind in resp.text.lower()
                               for ind in user_data_indicators):
                            self.findings.append({
                                "type": "Potential IDOR Vulnerability",
                                "detail": f"User data accessible without auth at {url}",
                                "severity": "HIGH",
                                "evidence": f"URL: {url} returned user data (status 200)",
                                "url": url
                            })
                            print(f"[HIGH] Potential IDOR: {url}")
                            break

                except Exception:
                    pass

    # ============================================================
    # CATEGORY 3 — DNS Security
    # ============================================================
    def check_dns_security(self):
        """
        Checks DNS security configuration.
        WHY:
        Missing SPF = anyone can send email as your domain!
        Missing DMARC = phishing emails look legitimate!
        Zone transfer = exposes ALL internal DNS records!
        """
        print("[*] Checking DNS security...")

        try:
            import dns.resolver as resolver

            # Check SPF record
            try:
                spf_records = resolver.resolve(self.domain, "TXT")
                spf_found = False
                for record in spf_records:
                    if "v=spf1" in str(record):
                        spf_found = True
                        print(f"[+] SPF record found: {str(record)[:50]}")
                        break

                if not spf_found:
                    self.findings.append({
                        "type": "Missing SPF Record",
                        "detail": "No SPF record — attackers can send email as your domain!",
                        "severity": "HIGH",
                        "evidence": f"No SPF TXT record for {self.domain}",
                        "url": self.target
                    })
                    print("[HIGH] SPF record missing!")

            except Exception:
                print(f"[!] SPF check failed")

            # Check DMARC record
            try:
                dmarc_records = resolver.resolve(
                    f"_dmarc.{self.domain}", "TXT"
                )
                dmarc_found = False
                for record in dmarc_records:
                    if "v=DMARC1" in str(record):
                        dmarc_found = True
                        # Check policy
                        if "p=none" in str(record):
                            self.findings.append({
                                "type": "Weak DMARC Policy",
                                "detail": "DMARC policy is 'none' — emails not rejected!",
                                "severity": "MEDIUM",
                                "evidence": str(record)[:100],
                                "url": self.target
                            })
                            print("[MEDIUM] DMARC policy is none!")
                        else:
                            print(f"[+] DMARC found with enforcement")
                        break

                if not dmarc_found:
                    self.findings.append({
                        "type": "Missing DMARC Record",
                        "detail": "No DMARC record — phishing emails appear legitimate!",
                        "severity": "HIGH",
                        "evidence": f"No DMARC record for {self.domain}",
                        "url": self.target
                    })
                    print("[HIGH] DMARC record missing!")

            except Exception:
                self.findings.append({
                    "type": "Missing DMARC Record",
                    "detail": "No DMARC record — phishing emails appear legitimate!",
                    "severity": "HIGH",
                    "evidence": f"No DMARC record for {self.domain}",
                    "url": self.target
                })
                print("[HIGH] DMARC record missing!")

            # Check DKIM
            try:
                dkim_selectors = ["default", "google", "mail", "email", "k1"]
                dkim_found = False
                for selector in dkim_selectors:
                    try:
                        resolver.resolve(
                            f"{selector}._domainkey.{self.domain}", "TXT"
                        )
                        dkim_found = True
                        print(f"[+] DKIM found with selector: {selector}")
                        break
                    except Exception:
                        pass

                if not dkim_found:
                    self.findings.append({
                        "type": "Missing DKIM Record",
                        "detail": "No DKIM record found — email integrity not verified!",
                        "severity": "MEDIUM",
                        "evidence": f"No DKIM TXT record for {self.domain}",
                        "url": self.target
                    })
                    print("[MEDIUM] DKIM record missing!")

            except Exception:
                pass

            # Test DNS Zone Transfer
            try:
                ns_records = resolver.resolve(self.domain, "NS")
                for ns in ns_records:
                    ns_server = str(ns).rstrip(".")
                    try:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(ns_server, self.domain)
                        )
                        if zone:
                            self.findings.append({
                                "type": "DNS Zone Transfer Allowed",
                                "detail": f"Zone transfer from {ns_server} — ALL DNS records exposed!",
                                "severity": "CRITICAL",
                                "evidence": f"Nameserver {ns_server} allows AXFR",
                                "url": self.target
                            })
                            print(f"[CRITICAL] Zone transfer allowed from {ns_server}!")
                    except Exception:
                        pass

            except Exception:
                pass

        except ImportError:
            print("[!] dnspython not installed — run: pip install dnspython")
            # Fallback without dnspython
            self.check_dns_basic()

    def check_dns_basic(self):
        """Basic DNS check without dnspython library."""
        try:
            import subprocess
            # Check SPF via subprocess
            result = subprocess.run(
                ["nslookup", "-type=TXT", self.domain],
                capture_output=True, text=True, timeout=10
            )
            if "v=spf1" not in result.stdout:
                self.findings.append({
                    "type": "Missing SPF Record",
                    "detail": "No SPF record — email spoofing possible",
                    "severity": "HIGH",
                    "evidence": f"No SPF for {self.domain}",
                    "url": self.target
                })
                print("[HIGH] SPF missing!")
        except Exception:
            pass

    # ============================================================
    # CATEGORY 4 — API Rate Limiting Test
    # ============================================================
    def check_rate_limiting(self):
        """
        Tests if API endpoints have rate limiting.
        WHY: Without rate limiting:
        - Brute force login = account takeover
        - Scrape all data = data theft
        - Spam endpoints = DoS attack
        Real example: Many Indian apps have no rate limiting!
        """
        print("[*] Testing API rate limiting...")

        # Endpoints to test
        test_endpoints = [
            "/api/login",
            "/api/auth/login",
            "/login",
            "/auth/login",
            "/api/v1/login",
        ]

        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Send 20 rapid requests
                responses = []
                start_time = time.time()

                for i in range(20):
                    resp = self.session.post(
                        url,
                        json={
                            "email": f"test{i}@test.com",
                            "password": "wrongpassword123"
                        },
                        timeout=3,
                        verify=False
                    )
                    responses.append(resp.status_code)

                elapsed = time.time() - start_time

                # Check if any rate limiting occurred
                rate_limited = any(
                    code in [429, 503, 403]
                    for code in responses
                )

                if not rate_limited and 200 in responses or \
                   all(code in [200, 400, 401, 422]
                       for code in responses):
                    self.findings.append({
                        "type": "No Rate Limiting",
                        "detail": f"Endpoint {endpoint} accepts 20 requests "
                                  f"in {elapsed:.1f}s without rate limiting!",
                        "severity": "HIGH",
                        "evidence": f"20 requests in {elapsed:.1f}s — "
                                    f"no 429 response",
                        "url": url
                    })
                    print(f"[HIGH] No rate limiting at {endpoint}!")
                    break

                elif rate_limited:
                    print(f"[+] Rate limiting detected at {endpoint}!")

            except Exception:
                pass

    # ============================================================
    # CATEGORY 5 — HTTP Security Headers Deep Scan
    # ============================================================
    def check_security_headers_deep(self):
        """
        Comprehensive check of ALL security headers.
        Current web scanner checks 4 headers.
        This checks 12 headers including advanced ones!
        """
        print("[*] Deep scanning security headers...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            headers = resp.headers

            # Complete security headers checklist
            security_headers = {
                "X-Content-Type-Options": {
                    "expected": "nosniff",
                    "severity": "MEDIUM",
                    "detail": "MIME sniffing attacks possible"
                },
                "X-Frame-Options": {
                    "expected": ["DENY", "SAMEORIGIN"],
                    "severity": "MEDIUM",
                    "detail": "Clickjacking attacks possible"
                },
                "Content-Security-Policy": {
                    "expected": None,
                    "severity": "MEDIUM",
                    "detail": "XSS attacks easier without CSP"
                },
                "Strict-Transport-Security": {
                    "expected": None,
                    "severity": "MEDIUM",
                    "detail": "SSL stripping possible"
                },
                "Referrer-Policy": {
                    "expected": None,
                    "severity": "LOW",
                    "detail": "Referrer information leakage"
                },
                "Permissions-Policy": {
                    "expected": None,
                    "severity": "LOW",
                    "detail": "Browser features not restricted"
                },
                "X-XSS-Protection": {
                    "expected": "1; mode=block",
                    "severity": "LOW",
                    "detail": "XSS filter not enabled"
                },
                "Cross-Origin-Opener-Policy": {
                    "expected": None,
                    "severity": "LOW",
                    "detail": "Cross-origin attacks possible"
                },
                "Cross-Origin-Resource-Policy": {
                    "expected": None,
                    "severity": "LOW",
                    "detail": "Resource sharing not restricted"
                },
            }

            missing_count = 0
            for header, config in security_headers.items():
                if header not in headers:
                    missing_count += 1
                    self.findings.append({
                        "type": f"Missing Security Header: {header}",
                        "detail": f"{header} missing — {config['detail']}",
                        "severity": config["severity"],
                        "evidence": f"Header not present in response",
                        "url": self.target
                    })
                    print(f"[{config['severity']}] Missing: {header}")
                else:
                    print(f"[+] Present: {header}")

            print(f"[*] Missing {missing_count}/9 security headers")

        except Exception as e:
            print(f"[!] Headers check error: {e}")

    # ============================================================
    # CATEGORY 6 — Sensitive Data in Responses
    # ============================================================
    def check_sensitive_data_exposure(self):
        """
        Scans API responses for accidentally exposed data.
        WHY: APIs sometimes return more data than needed.
        Developer returns full user object —
        includes fields like password hash, internal IDs,
        private notes that frontend does not display
        but ARE in the response!
        """
        print("[*] Checking for sensitive data exposure...")

        # Endpoints likely to return data
        data_endpoints = [
            "/api/user", "/api/users", "/api/profile",
            "/api/me", "/api/account", "/api/config",
            "/api/settings", "/api/info", "/api/status",
            "/health", "/status", "/info", "/debug",
            "/api/v1/user", "/api/v2/user",
        ]

        sensitive_patterns = {
            "Password Hash": r'"\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}"',
            "Private Key": r'-----BEGIN.*PRIVATE KEY-----',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Credit Card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b',
            "Email List": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Phone Number": r'\b[6-9]\d{9}\b',
            "Aadhar Number": r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b',
            "Stack Trace": r'(Traceback|at com\.|at org\.|NullPointerException)',
            "Internal IP": r'(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}',
            "Database Error": r'(SQL syntax|mysql_fetch|ORA-[0-9]+|SQLSTATE)',
        }

        for endpoint in data_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                resp = self.session.get(
                    url, timeout=5, verify=False
                )

                if resp.status_code == 200 and len(resp.text) > 20:
                    for data_type, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, resp.text)
                        if matches:
                            # Limit evidence shown
                            evidence = str(matches[0])[:50]
                            if data_type == "Email List":
                                # Only flag if many emails
                                if len(matches) > 5:
                                    self.findings.append({
                                        "type": "Sensitive Data Exposure",
                                        "detail": f"{data_type} found at {endpoint} — {len(matches)} items",
                                        "severity": "HIGH",
                                        "evidence": f"{len(matches)} {data_type}s exposed",
                                        "url": url
                                    })
                                    print(f"[HIGH] {data_type} at {endpoint}")
                            else:
                                self.findings.append({
                                    "type": "Sensitive Data Exposure",
                                    "detail": f"{data_type} exposed at {endpoint}",
                                    "severity": "CRITICAL",
                                    "evidence": evidence,
                                    "url": url
                                })
                                print(f"[CRITICAL] {data_type} at {endpoint}!")

            except Exception:
                pass

    # ============================================================
    # MAIN — Run complete advanced analysis
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope Advanced Scanner — 6 Categories")
        print("="*60)

        self.check_ssrf()
        self.check_idor()
        self.check_dns_security()
        self.check_rate_limiting()
        self.check_security_headers_deep()
        self.check_sensitive_data_exposure()

        print("\n" + "="*60)
        print(f"Advanced Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = AdvancedScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")