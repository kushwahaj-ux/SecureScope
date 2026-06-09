import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl
import socket
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FrontendAnalyzer:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.findings = []
        self.js_files = []
        self.visited_pages = set()
        self.all_js_content = {}
        print(f"Frontend Analyzer Ready! Target: {self.target}")

    # ============================================================
    # CATEGORY 1 — Crawl website and collect pages + JS files
    # ============================================================
    def crawl_website(self, max_pages=15):
        """
        Visits up to 15 pages on same domain.
        Collects all JavaScript files and inline scripts.
        WHY: More pages = more JS files = more chances to find secrets
        """
        print(f"[*] Crawling website — max {max_pages} pages...")
        # Start with homepage + important paths to ensure diverse crawling
        important_paths = [
            '', '/about', '/contact', '/login', '/account',
            '/cart', '/checkout', '/products', '/categories',
            '/blog', '/faq', '/privacy', '/terms', '/sitemap.xml'
        ]
        to_visit = [self.target] + [
            urljoin(self.target, path) 
            for path in important_paths
        ]
        base_domain = urlparse(self.target).netloc

        while to_visit and len(self.visited_pages) < max_pages:
            url = to_visit.pop(0)
            if url in self.visited_pages:
                continue
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                self.visited_pages.add(url)
                print(f"[*] Crawled: {url}")
                soup = BeautifulSoup(resp.text, "html.parser")

                # Find all internal links on same domain only
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(url, link["href"])
                    parsed = urlparse(full_url)
                    # Skip fragment URLs — not real pages
                    if parsed.fragment:
                        continue
                    # Skip non-HTTP URLs
                    if parsed.scheme not in ['http', 'https']:
                        continue
                    if parsed.netloc == base_domain and full_url not in self.visited_pages:
                        # Allow max 2 URLs with same path pattern
                        same_path_count = sum(
                            1 for u in to_visit + list(self.visited_pages)
                            if urlparse(u).path == parsed.path
                        )
                        if same_path_count < 2:
                            to_visit.append(full_url)

                # Find all JavaScript files
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        js_url = urljoin(url, src)
                        if js_url not in self.js_files:
                            self.js_files.append(js_url)
                    # Also capture inline scripts
                    elif script.string:
                        self.all_js_content[f"inline_{url}"] = script.string

            except Exception as e:
                print(f"[!] Error crawling {url}: {e}")

        print(f"[+] Crawled {len(self.visited_pages)} pages")
        print(f"[+] Found {len(self.js_files)} JavaScript files")

    # ============================================================
    # CATEGORY 2 — Download all JavaScript files
    # ============================================================
    def download_js_files(self):
        """
        Downloads every JS file found during crawling.
        WHY: Secrets and endpoints hide inside minified JS files
        """
        print("[*] Downloading JavaScript files...")
        for js_url in self.js_files:
            try:
                resp = self.session.get(js_url, timeout=10, verify=False)
                if resp.status_code == 200:
                    self.all_js_content[js_url] = resp.text
                    print(f"[+] Downloaded: {js_url[:80]}")
            except Exception as e:
                print(f"[!] Failed: {js_url[:60]} — {e}")

    # ============================================================
    # CATEGORY 3 — Sensitive Information Exposure
    # Find hardcoded API keys, passwords, tokens
    # ============================================================
    def check_hardcoded_secrets(self):
        """
        Scans JS files for accidentally exposed credentials.
        WHY: Developers forget to remove API keys before deploying
        Real example: Uber breach happened due to hardcoded AWS key in JS
        """
        print("[*] Scanning for hardcoded secrets...")

        secret_patterns = {
            "Google API Key":       r'AIza[0-9A-Za-z\-_]{35}',
            "AWS Access Key":       r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key":       r'(?i)aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
            "Stripe Live Key":      r'sk_live_[0-9a-zA-Z]{24}',
            "Stripe Test Key":      r'sk_test_[0-9a-zA-Z]{24}',
            "GitHub Token":         r'ghp_[0-9a-zA-Z]{36}',
            "JWT Token":            r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            "Private Key":          r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            "Password in Code":     r'(?i)(password|passwd|pwd)\s*=\s*[\'"][^\'"]{4,}[\'"]',
            "API Key Generic":      r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
            "Secret Key":           r'(?i)(secret_key|api_secret|auth_token|access_token|refresh_token)\s*[=:]\s*[\'"][^\'"]{20,}[\'"]',
            "Database URL":         r'(?i)(mongodb|postgresql|mysql|redis):\/\/[^\s\'"]+',
            "Basic Auth Header":    r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{10,}',
            "Slack Token":          r'xox[baprs]-[0-9A-Za-z]{10,}',
            "Firebase URL":         r'https://[a-z0-9-]+\.firebaseio\.com',
            "Twilio API Key":       r'SK[0-9a-fA-F]{32}',
        }

        for source, content in self.all_js_content.items():

            for secret_type, pattern in secret_patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    already_found = any(
                        f.get("type") == "Hardcoded Secret" and
                        f.get("detail", "").startswith(secret_type)
                        for f in self.findings
                    )
                    if not already_found:
                        self.findings.append({
                            "type": "Hardcoded Secret",
                            "detail": f"{secret_type} found in source code",
                            "severity": "CRITICAL",
                            "evidence": str(match)[:80] + "...",
                            "url": source
                        })
                        print(f"[CRITICAL] {secret_type} in: {source[:60]}")

    # ============================================================
    # CATEGORY 4 — API Security Misconfigurations
    # Find hidden sensitive endpoints in JavaScript
    # ============================================================
    def check_hidden_endpoints(self):
        """
        Extracts API endpoints from JS files.
        WHY: Developers hide admin/internal APIs in JS thinking nobody looks
        These endpoints often have no authentication
        """
        print("[*] Scanning for hidden API endpoints...")
        from verifier import establish_baseline, is_false_positive
    
    # Establish baseline first
        baseline = establish_baseline(self.target)

        endpoint_patterns = [
            r'[\'"`](/api/[^\s\'"`,)\]]+)',
            r'[\'"`](/v[0-9]/[^\s\'"`,)\]]+)',
            r'[\'"`](/admin/[^\s\'"`,)\]]+)',
            r'[\'"`](/internal/[^\s\'"`,)\]]+)',
            r'[\'"`](/private/[^\s\'"`,)\]]+)',
            r'[\'"`](/graphql[^\s\'"`,)\]]*)',
            r'fetch\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'axios\.[a-z]+\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'\$\.ajax\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'\.get\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'\.post\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'\.put\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
            r'\.delete\([\'"`]([^\s\'"`,)\]]+)[\'"`]',
        ]

        sensitive_keywords = [
            "admin", "internal", "private", "secret",
            "password", "token", "auth", "user", "delete",
            "update", "create", "backup", "config", "debug",
            "test", "dev", "staging", "root", "superuser"
        ]

        found_endpoints = set()

        for source, content in self.all_js_content.items():
            # Skip known framework files — false positives
            framework_files = [
            "framework", "polyfills", "webpack",
            "main-", "chunk", "runtime"
            ]
            for pattern in endpoint_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match in found_endpoints or len(match) < 3:
                        continue
                    found_endpoints.add(match)

                    if any(kw in match.lower() for kw in sensitive_keywords):

                    # Build full URL
                       if match.startswith("http"):
                        full_url = match
                    else:
                        full_url = urljoin(self.target, match)

                    try:
                        resp = self.session.get(
                            full_url, timeout=5,
                            verify=False,
                            allow_redirects=True
                        )

                        # Filter soft 404s
                        if baseline and is_false_positive(resp, baseline):
                            print(f"[INFO] Filtered soft 404: {match}")
                            continue

                        # Real endpoint if non-200 status
                        if resp.status_code in [401, 403, 405, 422]:
                            self.findings.append({
                                "type": "Hidden Sensitive Endpoint",
                                "detail": f"VERIFIED endpoint: {match} (status: {resp.status_code})",
                                "severity": "HIGH",
                                "evidence": match,
                                "url": source
                            })
                            print(f"[HIGH] VERIFIED endpoint: {match}")

                        # For 200 — only flag if content differs from homepage
                        elif resp.status_code == 200:
                            if not is_false_positive(resp, baseline):
                                self.findings.append({
                                    "type": "Hidden Sensitive Endpoint",
                                    "detail": f"Sensitive endpoint discovered: {match}",
                                    "severity": "HIGH",
                                    "evidence": match,
                                    "url": source
                                })
                                print(f"[HIGH] Hidden endpoint: {match}")
                            else:
                                print(f"[INFO] Filtered (same as homepage): {match}")

                    except Exception:
                        pass

    # ============================================================
    # CATEGORY 5 — Client Side Security Issues
    # Dangerous JavaScript patterns
    # ============================================================
    def check_client_side_security(self):
        """
        Finds dangerous JavaScript coding patterns.
        WHY: Bad frontend code creates vulnerabilities even if backend is secure
        """
        print("[*] Checking client-side security issues...")

        dangerous_patterns = {
            "eval() Usage": {
                "pattern": r'\beval\s*\(',
                "severity": "HIGH",
                "detail": "eval() executes arbitrary code — can be exploited for XSS"
            },
            "innerHTML Assignment": {
                "pattern": r'\.innerHTML\s*=\s*[^=]',
                "severity": "HIGH",
                "detail": "innerHTML assignment — major XSS vulnerability vector"
            },
            "document.write Usage": {
                "pattern": r'document\.write\s*\(',
                "severity": "MEDIUM",
                "detail": "document.write() — can introduce XSS if user input used"
            },
            "Weak MD5 Cryptography": {
                "pattern": r'\bmd5\s*\(',
                "severity": "HIGH",
                "detail": "MD5 is cryptographically broken — cracked in seconds"
            },
            "Weak SHA1 Cryptography": {
                "pattern": r'\bsha1\s*\(',
                "severity": "HIGH",
                "detail": "SHA1 is deprecated and vulnerable to collision attacks"
            },
            "Sensitive localStorage": {
                "pattern": r'localStorage\.setItem\s*\(\s*[\'"`](token|password|secret|key|auth|user)',
                "severity": "HIGH",
                "detail": "Sensitive data in localStorage — accessible to XSS attacks"
            },
            "Sensitive sessionStorage": {
                "pattern": r'sessionStorage\.setItem\s*\(\s*[\'"`](token|password|secret|key)',
                "severity": "MEDIUM",
                "detail": "Sensitive data in sessionStorage — accessible to XSS"
            },
            "Console Log Sensitive Data": {
                "pattern": r'console\.(log|error|warn)\s*\(.*?(password|token|secret|key|auth)',
                "severity": "MEDIUM",
                "detail": "Sensitive data logged to browser console — visible to anyone"
            },
            "SSL Verification Disabled": {
                "pattern": r'(?i)(rejectUnauthorized|verify)\s*:\s*false',
                "severity": "HIGH",
                "detail": "SSL verification disabled — man-in-the-middle attack possible"
            },
            "Hardcoded Internal IP": {
                "pattern": r'(?i)(http|https)://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}',
                "severity": "HIGH",
                "detail": "Internal IP address exposed — reveals network architecture"
            },
            "Hardcoded Localhost": {
                "pattern": r'(?i)(http|https)://localhost[:/]',
                "severity": "MEDIUM",
                "detail": "Localhost reference in production code — development artifact"
            },
            "Security TODO Comment": {
                "pattern": r'(?i)//\s*(todo|fixme|hack|bug).{0,50}(security|auth|password|key|token)',
                "severity": "LOW",
                "detail": "Unfinished security implementation found in comments"
            },
            "Postmessage Without Origin": {
                "pattern": r'addEventListener\s*\(\s*[\'"`]message[\'"`]',
                "severity": "MEDIUM",
                "detail": "postMessage listener — check if origin validation is missing"
            },
            "prototype Pollution": {
                "pattern": r'__proto__|constructor\[.prototype.\]',
                "severity": "HIGH",
                "detail": "Potential prototype pollution vulnerability"
            },
        }

        framework_files = [
            "framework", "polyfills", "webpack",
            "main-", "chunk", "runtime"
        ]

        for source, content in self.all_js_content.items():
            if any(fw in source.lower() for fw in framework_files):
                continue
            for issue_name, issue_data in dangerous_patterns.items():
                matches = re.findall(issue_data["pattern"], content, re.IGNORECASE)
                if matches:
                    already_found = any(
                        f.get("type") == issue_name and f.get("url") == source
                        for f in self.findings
                    )
                    if not already_found:
                        self.findings.append({
                            "type": issue_name,
                            "detail": issue_data["detail"],
                            "severity": issue_data["severity"],
                            "evidence": str(matches[0])[:80],
                            "url": source
                        })
                        print(f"[{issue_data['severity']}] {issue_name}: {source[:60]}")

    # ============================================================
    # CATEGORY 6 — Information Disclosure
    # Sensitive HTML comments left by developers
    # ============================================================
    def check_html_comments(self):
        """
        Finds sensitive information in HTML comments.
        WHY: Developers leave debug info, credentials, and TODOs in comments
        These are visible to anyone who views page source
        """
        print("[*] Checking HTML source for sensitive comments...")

        sensitive_patterns = [
            (r'<!--[^>]{0,200}(password|passwd)\s*[:=][^>]{0,100}-->', "Password in HTML comment"),
    (r'<!--[^>]{0,200}(api.?key|apikey)\s*[:=][^>]{0,100}-->', "API Key in HTML comment"),
    (r'<!--[^>]{0,200}(secret|token)\s*[:=][^>]{0,100}-->', "Secret in HTML comment"),
    (r'<!--\s*(TODO|FIXME):.{10,200}(security|auth|password|key|token)[^>]{0,100}-->', "Security TODO"),
    (r'<!--[^>]{0,200}(username|user)\s*[:=][^>]{0,100}-->', "Username in HTML comment"),
    (r'<!--[^>]{0,200}(database_url|db_host|db_user)\s*[:=][^>]{0,100}-->', "Database credentials"),

        ]

        for url in self.visited_pages:
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                for pattern, description in sensitive_patterns:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        self.findings.append({
                            "type": "Sensitive HTML Comment",
                            "detail": f"{description} at {url}",
                            "severity": "MEDIUM",
                            "evidence": str(match)[:80],
                            "url": url
                        })
                        print(f"[MEDIUM] {description}: {url}")
            except Exception:
                pass

    # ============================================================
    # CATEGORY 7 — Open Redirect Detection
    # ============================================================
    def check_open_redirects(self):
        print("[*] Checking for open redirects...")

        redirect_params = ["url", "redirect", "next", "return", "goto",
                          "location", "redirect_url", "return_url", "dest",
                          "destination", "redir", "redirect_to"]

        test_url = "https://evil-test-domain-securescope.com"

        for page_url in list(self.visited_pages)[:5]:

            for page_url in list(self.visited_pages)[:5]:
                # Skip URLs with fragments — redirect testing invalid on these
                if '#' in page_url:
                    continue    
            try:
                resp = self.session.get(page_url, timeout=5, verify=False)
                page_content = resp.text.lower()

                for param in redirect_params:
                    if f'"{param}"' not in page_content and f"'{param}'" not in page_content and f"name={param}" not in page_content:
                        continue

                    test = f"{page_url}?{param}={test_url}"
                    resp = self.session.get(
                        test, timeout=5,
                        allow_redirects=True,
                        verify=False
                    )
                    if (resp.history and
                        "evil-test-domain-securescope" in resp.url and
                        resp.url != page_url and
                        urlparse(resp.url).netloc == "evil-test-domain-securescope.com"):
                        self.findings.append({
                            "type": "Open Redirect",
                            "detail": f"Confirmed open redirect via '{param}' at {page_url}",
                            "severity": "HIGH",
                            "evidence": f"Redirected to: {resp.url[:80]}",
                            "url": page_url
                        })
                        print(f"[HIGH] CONFIRMED open redirect: {page_url}?{param}=")
            except Exception:
                pass

    # ============================================================
    # CATEGORY 8 — Directory Listing Exposure
    # ============================================================
    def check_directory_listing(self):
        """
        Checks if web server shows file listings in directories.
        WHY: Exposes all files including backups, configs, sensitive documents
        Like leaving your filing cabinet open in the street
        """
        print("[*] Checking for directory listing...")

        common_dirs = [
            "/uploads/", "/images/", "/img/", "/files/",
            "/backup/", "/backups/", "/assets/", "/static/",
            "/media/", "/documents/", "/docs/", "/data/",
            "/logs/", "/temp/", "/tmp/", "/cache/",
            "/js/", "/css/", "/fonts/", "/includes/"
        ]

        # Signs that directory listing is enabled
        listing_signatures = [
            "Index of /",
            "Directory listing for",
            "Parent Directory",
            "[DIR]",
            "Last modified",
        ]

        for directory in common_dirs:
            url = urljoin(self.target, directory)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    if any(sig in resp.text for sig in listing_signatures):
                        self.findings.append({
                            "type": "Directory Listing Exposed",
                            "detail": f"Directory listing enabled at {url}",
                            "severity": "HIGH",
                            "evidence": f"Directory contents visible at {directory}",
                            "url": url
                        })
                        print(f"[HIGH] Directory listing: {url}")
            except Exception:
                pass

    # ============================================================
    # CATEGORY 9 — SSL/TLS Security Assessment
    # ============================================================
    def check_ssl_tls(self):
        """
        Checks SSL certificate and configuration.
        WHY: Weak SSL = man-in-the-middle attacks possible
        Expired certificate = browser warnings = lost customer trust
        """
        print("[*] Checking SSL/TLS security...")

        parsed = urlparse(self.target)
        hostname = parsed.netloc
        port = 443

        try:
            import datetime
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Check certificate expiry
                    expire_date_str = cert.get("notAfter", "")
                    if expire_date_str:
                        expire_date = ssl.cert_time_to_seconds(expire_date_str)
                        days_left = (expire_date - __import__('time').time()) / 86400

                        if days_left < 30:
                            self.findings.append({
                                "type": "SSL Certificate Expiring",
                                "detail": f"Certificate expires in {int(days_left)} days",
                                "severity": "HIGH",
                                "evidence": f"Expires: {expire_date_str}",
                                "url": self.target
                            })
                            print(f"[HIGH] SSL expiring in {int(days_left)} days!")

                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            self.findings.append({
                                "type": "Weak SSL Cipher",
                                "detail": f"Weak cipher suite in use: {cipher_name}",
                                "severity": "HIGH",
                                "evidence": cipher_name,
                                "url": self.target
                            })
                            print(f"[HIGH] Weak cipher: {cipher_name}")
                        else:
                            print(f"[+] SSL cipher OK: {cipher_name}")

        except ssl.SSLError as e:
            self.findings.append({
                "type": "SSL Configuration Error",
                "detail": f"SSL error detected: {str(e)[:100]}",
                "severity": "CRITICAL",
                "evidence": str(e)[:100],
                "url": self.target
            })
            print(f"[CRITICAL] SSL error: {e}")
        except Exception as e:
            print(f"[!] SSL check skipped: {e}")

    # ============================================================
    # CATEGORY 10 — Technology Fingerprinting
    # ============================================================
    def check_technology_fingerprint(self):
        """
        Identifies what technologies the website uses.
        WHY: Knowing the tech stack helps find version-specific vulnerabilities
        Also checks if version numbers are exposed — version disclosure = hacker advantage
        """
        print("[*] Fingerprinting technologies...")

        try:
            resp = self.session.get(self.target, timeout=10, verify=False)
            headers = resp.headers
            html = resp.text

            tech_signatures = {
                "WordPress":    ["wp-content", "wp-includes", "wp-json"],
                "Drupal":       ["drupal.js", "drupal.min.js", "Drupal.settings"],
                "Joomla":       ["/media/jui/", "joomla", "/components/com_"],
                "Laravel":      ["laravel_session", "XSRF-TOKEN"],
                "Django":       ["csrfmiddlewaretoken", "django"],
                "React":        ["react.js", "react.min.js", "__REACT"],
                "Angular":      ["ng-version", "angular.js", "ng-app"],
                "Vue.js":       ["vue.js", "vue.min.js", "__vue__"],
                "jQuery":       ["jquery.js", "jquery.min.js"],
                "Bootstrap":    ["bootstrap.css", "bootstrap.min.css"],
                "PHP":          ["X-Powered-By: PHP", ".php"],
                "ASP.NET":      ["X-AspNet-Version", "ASP.NET"],
                "Apache":       ["Server: Apache"],
                "Nginx":        ["Server: nginx"],
            }

            detected_tech = []
            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if sig.lower() in html.lower() or sig.lower() in str(headers).lower():
                        detected_tech.append(tech)
                        break

            if detected_tech:
                print(f"[+] Technologies detected: {', '.join(detected_tech)}")

            # Check for version disclosure in headers
            version_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                               "X-Generator", "X-Drupal-Cache"]

            for header in version_headers:
                if header in headers:
                    self.findings.append({
                        "type": "Technology Version Disclosure",
                        "detail": f"Server reveals version: {header}: {headers[header]}",
                        "severity": "LOW",
                        "evidence": f"{header}: {headers[header]}",
                        "url": self.target
                    })
                    print(f"[LOW] Version disclosed: {header}: {headers[header]}")

        except Exception as e:
            print(f"[!] Fingerprinting error: {e}")

    # ============================================================
    # CATEGORY 11 — Authentication Weakness Detection
    # ============================================================
    def check_authentication_weaknesses(self):
        """
        Checks for weak authentication implementations.
        WHY: Weak auth = easy account takeover = data breach
        """
        print("[*] Checking authentication weaknesses...")

        try:
            resp = self.session.get(self.target, timeout=10, verify=False)
            headers = resp.headers

            # Check for missing security cookies
            if "Set-Cookie" in headers:
                cookies = headers["Set-Cookie"]

                if "httponly" not in cookies.lower():
                    self.findings.append({
                        "type": "Missing HttpOnly Cookie Flag",
                        "detail": "Session cookie missing HttpOnly flag — JavaScript can steal it",
                        "severity": "HIGH",
                        "evidence": cookies[:80],
                        "url": self.target
                    })
                    print("[HIGH] HttpOnly flag missing on cookie!")

                if "secure" not in cookies.lower():
                    self.findings.append({
                        "type": "Missing Secure Cookie Flag",
                        "detail": "Cookie transmitted over HTTP — interception possible",
                        "severity": "HIGH",
                        "evidence": cookies[:80],
                        "url": self.target
                    })
                    print("[HIGH] Secure flag missing on cookie!")

                if "samesite" not in cookies.lower():
                    self.findings.append({
                        "type": "Missing SameSite Cookie Flag",
                        "detail": "SameSite flag missing — CSRF attack possible",
                        "severity": "MEDIUM",
                        "evidence": cookies[:80],
                        "url": self.target
                    })
                    print("[MEDIUM] SameSite flag missing on cookie!")

            # Check for CSRF token in forms
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form", method=re.compile("post", re.I))
            for form in forms:
                csrf_fields = form.find_all("input", attrs={
                    "name": re.compile(r"csrf|token|nonce", re.I)
                })
                if not csrf_fields:
                    action = form.get("action", self.target)
                    self.findings.append({
                        "type": "Missing CSRF Protection",
                        "detail": f"POST form without CSRF token at {action}",
                        "severity": "HIGH",
                        "evidence": f"Form action: {action}",
                        "url": self.target
                    })
                    print(f"[HIGH] No CSRF token in form: {action}")

        except Exception as e:
            print(f"[!] Auth check error: {e}")

    # ============================================================
    # MAIN — Run complete frontend analysis
    # ============================================================
    def run_full_analysis(self):
        print("\n" + "="*60)
        print("SecureScope Frontend Analyzer — 11 Security Categories")
        print("="*60)

        # Step 1 — Collect data
        self.crawl_website(max_pages=15)
        self.download_js_files()

        # Step 2 — Run all checks
        self.check_hardcoded_secrets()       # Category 3
        self.check_hidden_endpoints()         # Category 4
        self.check_client_side_security()     # Category 5
        self.check_html_comments()            # Category 6
        self.check_open_redirects()           # Category 7
        self.check_directory_listing()        # Category 8
        self.check_ssl_tls()                  # Category 9
        self.check_technology_fingerprint()   # Category 10
        self.check_authentication_weaknesses() # Category 11

        print("\n" + "="*60)
        print(f"Frontend Analysis Complete!")
        print(f"Total Findings: {len(self.findings)}")

        # Summary by severity
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    analyzer = FrontendAnalyzer("https://sharpener.tech")
    findings = analyzer.run_full_analysis()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")