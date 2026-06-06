import requests
import re
import json
import time
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebSocketScanner:
    """
    SecureScope WebSocket Security Scanner
    ========================================
    Tests WebSocket connections for security vulnerabilities.

    WHY THIS MATTERS:
    Modern apps use WebSockets for:
    - Live chat features
    - Real-time notifications
    - Stock price updates
    - Gaming
    - Collaborative editing

    WebSocket vulnerabilities are RARE to find
    because almost no tool tests them!
    = Less competition = Higher chance of payout!

    OWASP Coverage:
    - Cross-Site WebSocket Hijacking (CSWSH)
    - WebSocket Message Injection
    - Missing Authentication
    - No Input Validation
    - Information Disclosure via WebSocket
    """

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
        self.ws_endpoints = []
        print(f"WebSocket Scanner Ready! Target: {self.target}")

    # ============================================================
    # STEP 1 — Find WebSocket Endpoints
    # ============================================================
    def find_websocket_endpoints(self):
        """
        Discovers WebSocket endpoints on website.

        HOW WE FIND THEM:
        1. Scan JavaScript files for ws:// or wss:// URLs
        2. Look for WebSocket constructor calls
        3. Check common WebSocket paths
        4. Look for Socket.io patterns

        WHY:
        Cannot test WebSocket security without
        finding the endpoints first!
        """
        print("[*] Finding WebSocket endpoints...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            soup = BeautifulSoup(resp.text, "html.parser")

            # WebSocket URL patterns in JavaScript
            ws_patterns = [
                r'wss?://[^\s\'"`,)]+',
                r'new WebSocket\([\'"`]([^\'"`,)]+)[\'"`]',
                r'new WebSocket\([^)]+\)',
                r'io\.connect\([\'"`]([^\'"`,)]+)[\'"`]',
                r'socket\.connect\([\'"`]([^\'"`,)]+)[\'"`]',
                r'[\'"`](/socket\.io[^\'"`,)]*)[\'"`]',
                r'[\'"`](/ws[^\'"`,)]*)[\'"`]',
                r'[\'"`](/websocket[^\'"`,)]*)[\'"`]',
                r'[\'"`](/chat[^\'"`,)]*)[\'"`]',
                r'[\'"`](/realtime[^\'"`,)]*)[\'"`]',
            ]

            # Search in inline scripts
            all_js = ""
            for script in soup.find_all("script"):
                all_js += script.string or ""

            # Search in linked JS files
            for script in soup.find_all("script", src=True):
                try:
                    js_url = urljoin(self.target, script["src"])
                    js_resp = self.session.get(
                        js_url, timeout=5, verify=False
                    )
                    all_js += js_resp.text
                except Exception:
                    pass

            # Find WebSocket endpoints
            for pattern in ws_patterns:
                matches = re.findall(pattern, all_js, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match and match not in self.ws_endpoints:
                        # Convert ws:// to wss:// for security
                        if match.startswith("ws://"):
                            self.findings.append({
                                "type": "Unencrypted WebSocket",
                                "detail": f"WebSocket using ws:// instead of wss:// — unencrypted!",
                                "severity": "HIGH",
                                "evidence": match[:80],
                                "url": self.target
                            })
                            print(f"[HIGH] Unencrypted WebSocket: {match[:60]}")

                        self.ws_endpoints.append(match)
                        print(f"[+] WebSocket endpoint: {match[:60]}")

            # Check common WebSocket paths
            common_ws_paths = [
                "/ws", "/websocket", "/socket",
                "/socket.io", "/chat", "/realtime",
                "/live", "/stream", "/feed",
                "/api/ws", "/api/websocket",
                "/ws/chat", "/ws/notify",
            ]

            for path in common_ws_paths:
                url = urljoin(self.target, path)
                try:
                    resp = self.session.get(
                        url, timeout=3, verify=False
                    )
                    # WebSocket upgrade response indicators
                    if resp.status_code in [101, 400, 426] or \
                       "websocket" in resp.headers.get(
                           "Upgrade", "").lower() or \
                       "websocket" in resp.text.lower():
                        if path not in self.ws_endpoints:
                            self.ws_endpoints.append(path)
                            print(f"[+] WebSocket path found: {path}")
                except Exception:
                    pass

            # Check for Socket.io
            socketio_url = urljoin(self.target, "/socket.io/socket.io.js")
            try:
                resp = self.session.get(
                    socketio_url, timeout=3, verify=False
                )
                if resp.status_code == 200 and "socket.io" in resp.text.lower():
                    if "/socket.io" not in self.ws_endpoints:
                        self.ws_endpoints.append("/socket.io")
                        print(f"[+] Socket.io detected!")
                        self.findings.append({
                            "type": "Socket.io Detected",
                            "detail": "Socket.io WebSocket library detected — test for CSWSH",
                            "severity": "INFO",
                            "evidence": "socket.io.js found at /socket.io/",
                            "url": socketio_url
                        })
            except Exception:
                pass

            print(f"[+] Total WebSocket endpoints: {len(self.ws_endpoints)}")

        except Exception as e:
            print(f"[!] WebSocket discovery error: {e}")

    # ============================================================
    # STEP 2 — Cross-Site WebSocket Hijacking (CSWSH)
    # ============================================================
    def check_cswsh(self):
        """
        Tests for Cross-Site WebSocket Hijacking.

        WHAT IS CSWSH:
        WebSocket connections use cookies for auth
        If no Origin check = any website can connect!

        ATTACK:
        1. Victim visits attacker's website
        2. Attacker's JS opens WebSocket to target
        3. Victim's cookies sent automatically!
        4. Attacker reads victim's private messages/data!

        WHY HIGH VALUE:
        Similar to CSRF but for WebSockets
        Can lead to account takeover
        Payout: $500-3000
        """
        print("[*] Testing Cross-Site WebSocket Hijacking (CSWSH)...")

        evil_origins = [
            "https://evil-securescope-test.com",
            "https://attacker.com",
            "null",
            f"https://evil.{self.domain}",
        ]

        for endpoint in self.ws_endpoints[:3]:
            # Build WebSocket URL
            if endpoint.startswith("ws"):
                ws_url = endpoint
            elif endpoint.startswith("/"):
                ws_url = f"wss://{self.domain}{endpoint}"
            else:
                ws_url = f"wss://{self.domain}/{endpoint}"

            # Convert to HTTP to test handshake
            http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

            for evil_origin in evil_origins:
                try:
                    # Send WebSocket upgrade request with evil origin
                    headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": evil_origin,
                    }

                    resp = self.session.get(
                        http_url,
                        headers=headers,
                        timeout=5,
                        verify=False
                    )

                    # 101 = WebSocket upgrade accepted!
                    if resp.status_code == 101:
                        self.findings.append({
                            "type": "Cross-Site WebSocket Hijacking",
                            "detail": f"WebSocket accepts connections from evil origin: {evil_origin}",
                            "severity": "HIGH",
                            "evidence": f"Status 101 with Origin: {evil_origin}",
                            "url": http_url
                        })
                        print(f"[HIGH] CSWSH vulnerable: {endpoint}")

                    # Check response headers for origin handling
                    acao = resp.headers.get(
                        "Access-Control-Allow-Origin", ""
                    )
                    if acao == "*" or evil_origin in acao:
                        self.findings.append({
                            "type": "WebSocket CORS Misconfiguration",
                            "detail": f"WebSocket endpoint allows all origins",
                            "severity": "MEDIUM",
                            "evidence": f"Access-Control-Allow-Origin: {acao}",
                            "url": http_url
                        })
                        print(f"[MEDIUM] WebSocket CORS issue: {endpoint}")

                except Exception:
                    pass

    # ============================================================
    # STEP 3 — WebSocket Authentication Check
    # ============================================================
    def check_ws_authentication(self):
        """
        Tests if WebSocket endpoints require authentication.

        WHY:
        Many developers secure HTTP endpoints
        But forget to secure WebSocket endpoints!
        = Anyone can connect and receive real-time data!
        """
        print("[*] Checking WebSocket authentication...")

        for endpoint in self.ws_endpoints[:5]:
            if endpoint.startswith("/"):
                http_url = urljoin(self.target, endpoint)
            else:
                http_url = endpoint.replace("wss://", "https://").replace("ws://", "http://")

            try:
                # Test without any authentication
                no_auth_session = requests.Session()
                no_auth_session.headers = {
                    "User-Agent": "Mozilla/5.0",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                }

                resp = no_auth_session.get(
                    http_url, timeout=5, verify=False
                )

                # 101 without auth = vulnerable!
                if resp.status_code == 101:
                    self.findings.append({
                        "type": "WebSocket No Authentication",
                        "detail": f"WebSocket accepts unauthenticated connections at {endpoint}",
                        "severity": "HIGH",
                        "evidence": "Status 101 without any credentials",
                        "url": http_url
                    })
                    print(f"[HIGH] No auth WebSocket: {endpoint}")

                # Check for token in URL requirement
                elif resp.status_code in [401, 403]:
                    print(f"[+] WebSocket properly authenticated: {endpoint}")

            except Exception:
                pass

    # ============================================================
    # STEP 4 — WebSocket Input Validation
    # ============================================================
    def check_ws_input_validation(self):
        """
        Tests WebSocket message injection vulnerabilities.

        WHY:
        WebSocket messages often not validated!
        XSS via WebSocket = stored XSS affecting all users!
        SQL injection via WebSocket = database access!

        These are VERY high value findings!
        """
        print("[*] Testing WebSocket input validation...")

        # Injection payloads
        ws_injection_payloads = [
            # XSS
            "<script>alert('WS_XSS')</script>",
            '"><script>alert(1)</script>',
            # SQL Injection
            "' OR '1'='1",
            "1; DROP TABLE users--",
            # Command Injection
            "; ls -la",
            "| whoami",
            # JSON Injection
            '{"type":"admin","role":"superuser"}',
            # Prototype Pollution
            '{"__proto__":{"isAdmin":true}}',
        ]

        for endpoint in self.ws_endpoints[:3]:
            if endpoint.startswith("/"):
                http_url = urljoin(self.target, endpoint)
            else:
                http_url = endpoint

            for payload in ws_injection_payloads[:3]:
                try:
                    # Send payload via HTTP POST to WebSocket endpoint
                    resp = self.session.post(
                        http_url,
                        json={"message": payload, "type": "chat"},
                        timeout=5,
                        verify=False
                    )

                    # Check if payload reflected
                    if payload in resp.text:
                        self.findings.append({
                            "type": "WebSocket Message Injection",
                            "detail": f"WebSocket reflects unvalidated input at {endpoint}",
                            "severity": "HIGH",
                            "evidence": f"Payload reflected: {payload[:50]}",
                            "url": http_url
                        })
                        print(f"[HIGH] WebSocket injection at {endpoint}!")

                except Exception:
                    pass

    # ============================================================
    # STEP 5 — WebSocket Information Disclosure
    # ============================================================
    def check_ws_info_disclosure(self):
        """
        Tests if WebSocket endpoints leak sensitive information.

        WHY:
        WebSocket error messages often reveal:
        - Server technology
        - Database errors
        - Internal paths
        - Debug information
        """
        print("[*] Checking WebSocket information disclosure...")

        for endpoint in self.ws_endpoints[:3]:
            if endpoint.startswith("/"):
                http_url = urljoin(self.target, endpoint)
            else:
                http_url = endpoint

            try:
                # Send malformed WebSocket request
                resp = self.session.get(
                    http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Sec-WebSocket-Version": "99",  # Invalid version
                    },
                    timeout=5,
                    verify=False
                )

                # Check for sensitive info in error response
                sensitive_patterns = [
                    r'(stack trace|traceback|exception)',
                    r'(mysql|postgresql|mongodb|redis)',
                    r'(internal server|debug|error)',
                    r'(/var/www|/home/|/app/)',
                    r'(version|v\d+\.\d+)',
                ]

                for pattern in sensitive_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self.findings.append({
                            "type": "WebSocket Information Disclosure",
                            "detail": f"WebSocket error reveals sensitive information",
                            "severity": "MEDIUM",
                            "evidence": f"Pattern '{pattern}' found in error response",
                            "url": http_url
                        })
                        print(f"[MEDIUM] Info disclosure via WebSocket!")
                        break

            except Exception:
                pass

    # ============================================================
    # STEP 6 — WebSocket Rate Limiting
    # ============================================================
    def check_ws_rate_limiting(self):
        """
        Tests if WebSocket connections are rate limited.

        WHY:
        Without rate limiting:
        - Spam messages to all connected users
        - DoS attack on WebSocket server
        - Brute force via WebSocket
        """
        print("[*] Testing WebSocket rate limiting...")

        for endpoint in self.ws_endpoints[:2]:
            if endpoint.startswith("/"):
                http_url = urljoin(self.target, endpoint)
            else:
                http_url = endpoint

            try:
                responses = []
                start = time.time()

                # Send 20 rapid requests
                for i in range(20):
                    try:
                        resp = self.session.post(
                            http_url,
                            json={"message": f"rate_test_{i}"},
                            timeout=2,
                            verify=False
                        )
                        responses.append(resp.status_code)
                    except Exception:
                        pass

                elapsed = time.time() - start

                # If all requests succeeded = no rate limiting
                if responses and 429 not in responses and \
                   len(responses) >= 15:
                    self.findings.append({
                        "type": "WebSocket No Rate Limiting",
                        "detail": f"WebSocket endpoint accepts unlimited messages",
                        "severity": "MEDIUM",
                        "evidence": f"{len(responses)} requests in {elapsed:.1f}s without throttling",
                        "url": http_url
                    })
                    print(f"[MEDIUM] No rate limiting: {endpoint}")

            except Exception:
                pass

    # ============================================================
    # MAIN — Run complete WebSocket scan
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope WebSocket Security Scanner")
        print("="*60)

        # Step 1 — Find endpoints first
        self.find_websocket_endpoints()

        if not self.ws_endpoints:
            print("[!] No WebSocket endpoints found!")
            print("[*] Website may not use WebSockets")
            return self.findings

        print(f"\n[+] Testing {len(self.ws_endpoints)} WebSocket endpoints...")

        # Run all security tests
        self.check_cswsh()
        self.check_ws_authentication()
        self.check_ws_input_validation()
        self.check_ws_info_disclosure()
        self.check_ws_rate_limiting()

        print("\n" + "="*60)
        print(f"WebSocket Scan Complete!")
        print(f"Endpoints Found: {len(self.ws_endpoints)}")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        info = sum(1 for f in self.findings if f["severity"] == "INFO")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | INFO: {info}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = WebSocketScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")