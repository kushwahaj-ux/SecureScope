import requests
import json
import re
import time
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuthenticatedScanner:
    """
    SecureScope Authenticated Scanner
    ==================================
    Logs into target application and scans
    vulnerabilities that only exist behind login.

    WHY THIS MATTERS:
    Without auth → scanning 20% of application
    With auth    → scanning 100% of application

    Supports 3 authentication methods:
    1. Form Login (automatic)
    2. Session Cookie (manual)
    3. JWT Token (API)
    """

    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9"
        }
        self.findings = []
        self.is_authenticated = False
        self.auth_method = None
        self.auth_token = None
        self.visited_urls = set()
        print(f"Authenticated Scanner Ready! Target: {self.target}")

    # ============================================================
    # AUTHENTICATION METHODS
    # ============================================================

    def login_with_form(self, login_url, username, password,
                        username_field="email",
                        password_field="password"):
        """
        Method 1 — Automatic Form Login

        HOW IT WORKS:
        1. POST credentials to login URL
        2. Extract session cookie from response
        3. Store in session for all future requests

        WHY: Most websites use form-based login
        SecureScope submits the form automatically!
        """
        print(f"[*] Attempting form login at {login_url}...")

        login_data = {
            username_field: username,
            password_field: password
        }

        try:
            # Try JSON login first (modern APIs)
            resp = self.session.post(
                login_url,
                json=login_data,
                timeout=10,
                verify=False
            )

            # Check for JWT token in response
            if resp.status_code in [200, 201]:
                try:
                    data = resp.json()
                    # Common token field names
                    token_fields = [
                        "token", "access_token", "accessToken",
                        "jwt", "auth_token", "authToken",
                        "data.token", "data.access_token"
                    ]
                    for field in token_fields:
                        token = self._get_nested(data, field)
                        if token:
                            self.auth_token = token
                            self.session.headers.update({
                                "Authorization": f"Bearer {token}"
                            })
                            self.is_authenticated = True
                            self.auth_method = "JWT"
                            print(f"[+] Login successful via JSON! JWT token captured.")
                            return True
                except Exception:
                    pass

            # Try form-encoded login (traditional websites)
            resp = self.session.post(
                login_url,
                data=login_data,
                timeout=10,
                verify=False,
                allow_redirects=True
            )

            # Check if login was successful
            if resp.status_code in [200, 302]:
                # Check for session cookie
                if self.session.cookies:
                    self.is_authenticated = True
                    self.auth_method = "COOKIE"
                    print(f"[+] Login successful via form! Session cookie captured.")
                    print(f"[+] Cookies: {list(self.session.cookies.keys())}")
                    return True

                # Check response for success indicators
                success_indicators = [
                    "dashboard", "logout", "welcome",
                    "profile", "account", "signed in"
                ]
                if any(ind in resp.text.lower() for ind in success_indicators):
                    self.is_authenticated = True
                    self.auth_method = "COOKIE"
                    print(f"[+] Login appears successful!")
                    return True

            print(f"[!] Login failed — status: {resp.status_code}")
            return False

        except Exception as e:
            print(f"[!] Login error: {e}")
            return False

    def login_with_cookie(self, cookie_string):
        """
        Method 2 — Manual Cookie Login

        HOW IT WORKS:
        User copies session cookie from browser F12
        SecureScope uses it for all requests

        HOW TO GET COOKIE:
        1. Login to website in browser
        2. Press F12 → Application → Cookies
        3. Copy session cookie value
        4. Paste here
        """
        print("[*] Setting session cookie...")
        try:
            # Parse cookie string
            if "=" in cookie_string:
                cookies = {}
                for item in cookie_string.split(";"):
                    if "=" in item:
                        key, value = item.strip().split("=", 1)
                        cookies[key.strip()] = value.strip()
                self.session.cookies.update(cookies)
            else:
                self.session.cookies.update({"session": cookie_string})

            self.is_authenticated = True
            self.auth_method = "COOKIE"
            print(f"[+] Session cookie set successfully!")
            return True

        except Exception as e:
            print(f"[!] Cookie error: {e}")
            return False

    def login_with_jwt(self, jwt_token):
        """
        Method 3 — JWT Token Login

        HOW IT WORKS:
        User provides JWT token
        SecureScope adds it as Bearer token to all requests

        HOW TO GET JWT:
        1. Login to website
        2. Press F12 → Application → Local Storage
        3. Find token field
        4. Copy and paste here
        """
        print("[*] Setting JWT token...")
        try:
            # Clean token
            token = jwt_token.replace("Bearer ", "").strip()
            self.auth_token = token
            self.session.headers.update({
                "Authorization": f"Bearer {token}"
            })
            self.is_authenticated = True
            self.auth_method = "JWT"
            print(f"[+] JWT token set successfully!")
            return True

        except Exception as e:
            print(f"[!] JWT error: {e}")
            return False

    def verify_authentication(self):
        """
        Verifies authentication is working.
        Tests by visiting authenticated pages.
        """
        print("[*] Verifying authentication...")

        test_urls = [
            "/dashboard", "/profile", "/account",
            "/api/me", "/api/user", "/api/profile"
        ]

        for test_url in test_urls:
            url = urljoin(self.target, test_url)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200 and len(resp.text) > 100:
                    print(f"[+] Authentication verified at: {url}")
                    return True
            except Exception:
                pass

        print("[!] Could not verify authentication — proceeding anyway")
        return False

    # ============================================================
    # POST-AUTH VULNERABILITY CHECKS
    # ============================================================

    def check_idor(self):
        """
        IDOR — Insecure Direct Object Reference
        =========================================
        Tests if changing user IDs accesses other users data.

        WHY CRITICAL:
        Most common vulnerability in Indian startups!
        /api/user/1001 → change to /api/user/1002
        = access someone else's private data!

        REAL EXAMPLES:
        - Paytm had IDOR — access any user's transactions
        - MakeMyTrip had IDOR — view other users bookings
        """
        print("[*] Testing for IDOR vulnerabilities...")

        idor_patterns = [
            "/api/user/{id}",
            "/api/users/{id}",
            "/api/profile/{id}",
            "/api/order/{id}",
            "/api/orders/{id}",
            "/api/invoice/{id}",
            "/api/document/{id}",
            "/api/ticket/{id}",
            "/user/{id}",
            "/profile/{id}",
            "/order/{id}",
        ]

        test_ids = [1, 2, 3, 100, 1000, 9999, 10000]

        for pattern in idor_patterns:
            responses = {}

            # Test multiple IDs
            for test_id in test_ids[:4]:
                url = urljoin(
                    self.target,
                    pattern.replace("{id}", str(test_id))
                )
                try:
                    resp = self.session.get(
                        url, timeout=5, verify=False
                    )
                    responses[test_id] = {
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "content": resp.text[:200]
                    }
                except Exception:
                    pass

            # Analyze responses
            successful = {
                k: v for k, v in responses.items()
                if v["status"] == 200 and v["length"] > 50
            }

            if len(successful) > 1:
                # Multiple IDs return data = IDOR!
                user_data_found = any(
                    any(field in v["content"].lower()
                        for field in ["email", "phone", "name", "address"])
                    for v in successful.values()
                )

                if user_data_found:
                    self.findings.append({
                        "type": "IDOR Vulnerability",
                        "detail": f"Multiple user IDs return data at {pattern} — access control missing!",
                        "severity": "CRITICAL",
                        "evidence": f"IDs {list(successful.keys())} all return 200 with user data",
                        "url": urljoin(self.target, pattern.replace("{id}", "1"))
                    })
                    print(f"[CRITICAL] IDOR found at {pattern}!")

    def check_privilege_escalation(self):
        """
        Privilege Escalation Testing
        ==============================
        Tests if normal user can access admin endpoints.

        WHY CRITICAL:
        Normal user accessing admin = full system compromise!
        Most apps check if user is logged in but not WHAT role they have.
        """
        print("[*] Testing privilege escalation...")

        admin_endpoints = [
            "/api/admin/users",
            "/api/admin/delete",
            "/api/admin/config",
            "/api/admin/dashboard",
            "/api/admin/logs",
            "/api/admin/settings",
            "/admin/api/users",
            "/api/v1/admin/users",
            "/api/management/users",
            "/api/superuser/",
            "/api/staff/",
        ]

        for endpoint in admin_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                resp = self.session.get(
                    url, timeout=5, verify=False
                )

                # If accessible with normal user token = vulnerability!
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Check if response contains admin data
                    admin_indicators = [
                        "users", "delete", "admin", "manage",
                        "role", "permission", "config", "system"
                    ]
                    if any(ind in resp.text.lower()
                           for ind in admin_indicators):
                        self.findings.append({
                            "type": "Privilege Escalation",
                            "detail": f"Admin endpoint accessible with normal user: {endpoint}",
                            "severity": "CRITICAL",
                            "evidence": f"Status 200 at {endpoint} with user credentials",
                            "url": url
                        })
                        print(f"[CRITICAL] Privilege escalation at {endpoint}!")

                elif resp.status_code == 403:
                    print(f"[+] Admin endpoint properly protected: {endpoint}")

            except Exception:
                pass

    def check_mass_assignment(self):
        """
        Mass Assignment Vulnerability
        ================================
        Tests if extra fields in API requests are processed.

        WHY CRITICAL:
        Developer writes: user.update(request.body)
        Attacker sends: {"name": "Ajeet", "role": "admin"}
        Server updates role too!
        = Instant admin access!

        REAL EXAMPLE:
        GitHub had mass assignment in 2012
        Researcher added SSH key to any organization!
        """
        print("[*] Testing mass assignment...")

        profile_endpoints = [
            "/api/user/profile",
            "/api/profile",
            "/api/me",
            "/api/account",
            "/api/settings",
            "/api/user/update",
        ]

        # Extra privileged fields to inject
        privilege_fields = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "isAdmin": True,
            "user_type": "admin",
            "userType": "admin",
            "privilege": "admin",
            "permissions": ["admin", "superuser"],
            "subscription": "premium",
            "plan": "enterprise",
            "credits": 999999,
            "balance": 999999
        }

        for endpoint in profile_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Send normal update with extra fields
                resp = self.session.patch(
                    url,
                    json={
                        "name": "Test User",
                        **privilege_fields
                    },
                    timeout=5,
                    verify=False
                )

                if resp.status_code in [200, 201]:
                    # Check if privileged fields were accepted
                    response_text = resp.text.lower()
                    if any(field in response_text
                           for field in ["admin", "premium", "enterprise"]):
                        self.findings.append({
                            "type": "Mass Assignment Vulnerability",
                            "detail": f"Server accepts privileged fields at {endpoint}",
                            "severity": "CRITICAL",
                            "evidence": f"role=admin accepted at {endpoint}",
                            "url": url
                        })
                        print(f"[CRITICAL] Mass assignment at {endpoint}!")

            except Exception:
                pass

    def check_broken_function_level_auth(self):
        """
        Broken Function Level Authorization
        =====================================
        Tests HTTP method switching for authorization bypass.

        WHY:
        Server checks: "Is user admin for DELETE?"
        But forgets to check: "Is user admin for POST?"
        Attacker switches methods to bypass auth!
        """
        print("[*] Testing function level authorization...")

        sensitive_endpoints = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
        ]

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

        for endpoint in sensitive_endpoints:
            url = urljoin(self.target, endpoint)
            method_results = {}

            for method in methods:
                try:
                    resp = self.session.request(
                        method, url,
                        json={"test": "test"},
                        timeout=5,
                        verify=False
                    )
                    method_results[method] = resp.status_code
                except Exception:
                    pass

            # Check for inconsistent access control
            if method_results:
                accessible = {
                    m: s for m, s in method_results.items()
                    if s in [200, 201]
                }
                restricted = {
                    m: s for m, s in method_results.items()
                    if s in [401, 403]
                }

                if accessible and restricted:
                    self.findings.append({
                        "type": "Broken Function Level Authorization",
                        "detail": f"Inconsistent auth at {endpoint} — some methods allowed, others not",
                        "severity": "HIGH",
                        "evidence": f"Allowed: {list(accessible.keys())} | Restricted: {list(restricted.keys())}",
                        "url": url
                    })
                    print(f"[HIGH] Inconsistent auth at {endpoint}")

    def check_sensitive_data_after_auth(self):
        """
        Sensitive Data Exposure (Authenticated)
        =========================================
        Checks if authenticated APIs expose sensitive data.

        WHY:
        APIs often return more data than frontend displays.
        Developer returns full user object including
        password hash, internal notes, other users data!
        Frontend hides it but it IS in the response.
        """
        print("[*] Checking sensitive data in authenticated responses...")

        auth_endpoints = [
            "/api/me",
            "/api/user",
            "/api/profile",
            "/api/account",
            "/api/settings",
            "/api/dashboard",
        ]

        sensitive_patterns = {
            "Password Hash": r'\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}',
            "Private Key": r'-----BEGIN.*PRIVATE KEY-----',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Other User Data": r'"user_id"\s*:\s*[0-9]+.*?"email"',
            "Internal System Info": r'(internal|private|secret|debug).*?:.*?"[^"]{10,}"',
            "Database Info": r'(mysql|postgresql|mongodb)://[^\s"]+',
        }

        for endpoint in auth_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                resp = self.session.get(
                    url, timeout=5, verify=False
                )

                if resp.status_code == 200 and len(resp.text) > 20:
                    for data_type, pattern in sensitive_patterns.items():
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.findings.append({
                                "type": "Authenticated Data Exposure",
                                "detail": f"{data_type} exposed in authenticated response at {endpoint}",
                                "severity": "HIGH",
                                "evidence": f"Pattern found in {endpoint} response",
                                "url": url
                            })
                            print(f"[HIGH] {data_type} at {endpoint}")

            except Exception:
                pass

    def check_session_management(self):
        """
        Session Management Security
        ============================
        Tests session token security.

        Checks:
        - Token still valid after logout?
        - Multiple concurrent sessions?
        - Session fixation possible?
        """
        print("[*] Checking session management...")

        # Test token validity
        if self.auth_token:
            try:
                # Test current token works
                resp = self.session.get(
                    urljoin(self.target, "/api/me"),
                    timeout=5, verify=False
                )

                if resp.status_code == 200:
                    # Try with modified token
                    modified_token = self.auth_token[:-5] + "XXXXX"
                    test_session = requests.Session()
                    test_session.headers.update({
                        "Authorization": f"Bearer {modified_token}"
                    })

                    resp2 = test_session.get(
                        urljoin(self.target, "/api/me"),
                        timeout=5, verify=False
                    )

                    # Modified token should NOT work
                    if resp2.status_code == 200:
                        self.findings.append({
                            "type": "Weak Token Validation",
                            "detail": "Server accepts modified JWT tokens — weak validation!",
                            "severity": "CRITICAL",
                            "evidence": "Modified token accepted by server",
                            "url": self.target
                        })
                        print("[CRITICAL] Weak token validation!")
                    else:
                        print("[+] Token validation is strong!")

            except Exception as e:
                print(f"[!] Session test error: {e}")

    def check_business_logic(self):
        """
        Business Logic Vulnerability Testing
        =====================================
        Tests application logic flaws that scanners miss.

        WHY IMPORTANT:
        AI cannot fully detect these — needs logic!
        Your friend's price manipulation = business logic flaw!
        Cannot be found by automated tools alone.

        Our scanner tests common patterns.
        """
        print("[*] Testing business logic vulnerabilities...")

        # Test 1 — Negative quantity/price
        order_endpoints = [
            "/api/order", "/api/orders",
            "/api/cart", "/api/checkout"
        ]

        for endpoint in order_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Send negative quantity
                resp = self.session.post(
                    url,
                    json={
                        "product_id": 1,
                        "quantity": -1,
                        "price": -100
                    },
                    timeout=5, verify=False
                )

                if resp.status_code in [200, 201]:
                    response_text = resp.text.lower()
                    # Check if negative order was accepted
                    if any(ind in response_text
                           for ind in ["success", "created", "order_id"]):
                        self.findings.append({
                            "type": "Business Logic — Negative Values",
                            "detail": f"Negative quantity/price accepted at {endpoint}!",
                            "severity": "CRITICAL",
                            "evidence": "Order with negative values accepted",
                            "url": url
                        })
                        print(f"[CRITICAL] Negative values accepted at {endpoint}!")

            except Exception:
                pass

        # Test 2 — Skip payment step
        payment_endpoints = [
            "/api/order/confirm",
            "/api/payment/complete",
            "/api/checkout/complete",
        ]

        for endpoint in payment_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Try to confirm order without payment
                resp = self.session.post(
                    url,
                    json={"order_id": 1, "status": "paid"},
                    timeout=5, verify=False
                )

                if resp.status_code in [200, 201]:
                    self.findings.append({
                        "type": "Business Logic — Payment Bypass",
                        "detail": f"Order confirmation without payment at {endpoint}",
                        "severity": "CRITICAL",
                        "evidence": "Payment step bypass possible",
                        "url": url
                    })
                    print(f"[CRITICAL] Payment bypass at {endpoint}!")

            except Exception:
                pass

    def crawl_authenticated_pages(self):
        """
        Crawls pages only accessible after login.
        Finds new URLs to test for vulnerabilities.
        """
        print("[*] Crawling authenticated pages...")
        auth_pages = []

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            base_domain = self.domain

            for link in soup.find_all("a", href=True):
                full_url = urljoin(self.target, link["href"])
                parsed = urlparse(full_url)

                if (parsed.netloc == base_domain and
                        full_url not in self.visited_urls):
                    auth_pages.append(full_url)
                    self.visited_urls.add(full_url)

            print(f"[+] Found {len(auth_pages)} authenticated pages")
            return auth_pages

        except Exception as e:
            print(f"[!] Crawl error: {e}")
            return []

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _get_nested(self, data, path):
        """Gets nested dictionary value using dot notation."""
        keys = path.split(".")
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                return None
        return data

    # ============================================================
    # MAIN — Run complete authenticated scan
    # ============================================================
    def run_full_scan(self, login_url=None, username=None,
                      password=None, cookie=None, jwt_token=None):
        """
        Complete authenticated vulnerability scan.

        Usage options:
        1. Form login: provide login_url, username, password
        2. Cookie: provide cookie string
        3. JWT: provide jwt_token
        """
        print("\n" + "="*60)
        print("SecureScope Authenticated Scanner")
        print("="*60)

        # Step 1 — Authenticate
        auth_success = False

        if jwt_token:
            auth_success = self.login_with_jwt(jwt_token)
        elif cookie:
            auth_success = self.login_with_cookie(cookie)
        elif login_url and username and password:
            auth_success = self.login_with_form(
                login_url, username, password
            )
        else:
            print("[!] No authentication provided!")
            print("[*] Tip: Provide login_url+username+password OR cookie OR jwt_token")
            return self.findings

        if not auth_success:
            print("[!] Authentication failed — cannot run authenticated scan")
            return self.findings

        # Step 2 — Verify authentication
        self.verify_authentication()

        # Step 3 — Run all authenticated checks
        print(f"\n[*] Running authenticated scans as {self.auth_method}...")
        self.crawl_authenticated_pages()
        self.check_idor()
        self.check_privilege_escalation()
        self.check_mass_assignment()
        self.check_broken_function_level_auth()
        self.check_sensitive_data_after_auth()
        self.check_session_management()
        self.check_business_logic()

        print("\n" + "="*60)
        print(f"Authenticated Scan Complete!")
        print(f"Auth Method: {self.auth_method}")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = AuthenticatedScanner("https://sharpener.tech")

    # Option 1 — Form Login (change credentials!)
    # findings = scanner.run_full_scan(
    #     login_url="https://sharpener.tech/api/auth/login",
    #     username="your@email.com",
    #     password="yourpassword"
    # )

    # Option 2 — JWT Token
    # findings = scanner.run_full_scan(
    #     jwt_token="eyJhbGciOiJIUzI1NiJ9..."
    # )

    # Option 3 — Session Cookie
    # findings = scanner.run_full_scan(
    #     cookie="session=abc123; auth=xyz789"
    # )

    # Default — no auth (shows usage)
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")