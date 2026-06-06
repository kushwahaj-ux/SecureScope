import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "SecureScope-Scanner/1.0"
        }
        self.findings = []
        print(f"Web Scanner Ready! Target: {self.target}")

    def check_security_headers(self):
        resp = self.session.get(self.target, timeout=30, verify=False)
        required = {
            "X-Content-Type-Options": "Prevents MIME sniffing attacks",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "Content-Security-Policy": "Controls resource loading",
            "Strict-Transport-Security": "Forces HTTPS connections",
        }
        for header, desc in required.items():
            if header not in resp.headers:
                self.findings.append({
                    "type": "Missing Security Header",
                    "detail": f"{header} - {desc}",
                    "severity": "MEDIUM",
                    "url": self.target
                })
                print(f"[MEDIUM] Missing: {header}")

    def check_sql_injection(self, url, params):
        payloads = ["'", "'OR'1'='1", "1 UNION SELECT NULL--"]
        errors = ["sql syntax", "mysql_fetch", "ORA-", "syntax error"]
        for payload in payloads:
            test = {k: payload for k in params}
            try:
                resp = self.session.get(url, params=test, timeout=10, verify=False)
                for err in errors:
                    if err.lower() in resp.text.lower():
                        self.findings.append({
                            "type": "SQL Injection",
                            "detail": f"Payload '{payload}' triggered error at {url}",
                            "severity": "CRITICAL",
                            "url": url
                        })
                        print(f"[CRITICAL] SQL Injection found at {url}")
                        return
            except Exception:
                pass

    def check_admin_panels(self):
        paths = [
            "/admin", "/administrator", "/wp-admin",
            "/login", "/dashboard", "/cpanel",
            "/phpmyadmin", "/manage"
        ]
        for path in paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=5,
                                        allow_redirects=False,
                                        verify=False)
                if resp.status_code in [401, 403]:
                    self.findings.append({
                        "type": "Exposed Admin Panel",
                        "detail": f"Panel found at {url} status {resp.status_code}",
                        "severity": "HIGH",
                        "url": url
                    })
                    print(f"[HIGH] Admin panel found: {url}")
                elif resp.status_code == 200:
                    admin_keywords = [
                        "dashboard", "admin panel", "control panel",
                        "manage", "administrator", "phpMyAdmin",
                        "server status", "file manager"
                    ]
                    if any(word in resp.text.lower() for word in admin_keywords):
                        self.findings.append({
                            "type": "Exposed Admin Panel",
                            "detail": f"Real admin panel confirmed at {url}",
                            "severity": "HIGH",
                            "url": url
                        })
                        print(f"[HIGH] Real admin panel confirmed: {url}")
                    else:
                        print(f"[INFO] Login page found at {url} — not flagged")
            except Exception:
                pass

    def check_sensitive_files(self):
        print("[*] Checking sensitive files...")
        from verifier import establish_baseline, is_false_positive

        baseline = establish_baseline(self.target)
        print(f"[*] Baseline established for false positive detection")

        files = [
            ".env", "config.php", ".git/config",
            "wp-config.php", "phpinfo.php",
            "backup.zip", "db_backup.sql",
            ".htpasswd", "web.config"
        ]

        real_content_signatures = {
            ".git/config": ["[core]", "repositoryformatversion", "filemode"],
            "db_backup.sql": ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump"],
            ".env": ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL"],
            "config.php": ["<?php", "define(", "DB_HOST", "DB_NAME"],
            "wp-config.php": ["<?php", "DB_NAME", "DB_USER", "DB_PASSWORD"],
            "phpinfo.php": ["phpinfo()", "PHP Version", "php.ini"],
            ".htpasswd": ["htpasswd", ":$apr1$", ":$2y$"],
            "backup.zip": ["PK"],
            "web.config": ["<configuration>", "connectionStrings", "appSettings"]
        }

        for f in files:
            url = urljoin(self.target, f)
            try:
                resp = self.session.get(url, timeout=5, verify=False)

                if resp.status_code == 200 and len(resp.text) > 10:

                    # Step 1 — Check against baseline
                    if is_false_positive(resp, baseline):
                        print(f"[INFO] False positive filtered: {url}")
                        continue

                    # Step 2 — Verify real content signatures
                    signatures = real_content_signatures.get(f, [])
                    if signatures:
                        found_signature = any(
                            sig.lower() in resp.text.lower()
                            for sig in signatures
                        )
                        if not found_signature:
                            print(f"[INFO] No real content — filtered: {url}")
                            continue

                    # Step 3 — Real finding confirmed!
                    self.findings.append({
                        "type": "Sensitive File Exposed",
                        "detail": f"{f} publicly accessible at {url}",
                        "severity": "CRITICAL",
                        "url": url
                    })
                    print(f"[CRITICAL] Sensitive file CONFIRMED: {url}")

            except Exception:
                pass

    def check_xss(self, url, params):
        payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>"
        ]
        for payload in payloads:
            test = {k: payload for k in params}
            try:
                resp = self.session.get(url, params=test,
                                        timeout=10, verify=False)
                if payload in resp.text:
                    self.findings.append({
                        "type": "Cross-Site Scripting XSS",
                        "detail": f"Reflected XSS found at {url}",
                        "severity": "HIGH",
                        "url": url
                    })
                    print(f"[HIGH] XSS found at {url}")
                    return
            except Exception:
                pass

    def crawl_forms(self):
        print("[*] Crawling forms...")
        try:
            resp = self.session.get(self.target, timeout=30, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(self.target, form.get("action", self.target))
                params = {
                    i.get("name", "f"): "test"
                    for i in form.find_all("input")
                    if i.get("name")
                }
                if params:
                    print(f"[*] Testing form at {action}")
                    self.check_sql_injection(action, params)
                    self.check_xss(action, params)
        except Exception as e:
            print(f"Crawl error: {e}")

if __name__ == "__main__":
    scanner = WebVulnerabilityScanner("https://ioaglobal.co.in/")
    scanner.check_security_headers()
    scanner.check_admin_panels()
    scanner.check_sensitive_files()
    scanner.crawl_forms()
    print(f"\nTotal findings: {len(scanner.findings)}")
    for f in scanner.findings:
        print(f"[{f['severity']}] {f['type']}: {f['detail']}")