import requests
import socket
import concurrent.futures
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SubdomainScanner:
    def __init__(self, target_url):
        parsed = urlparse(target_url)
        self.domain = parsed.netloc or target_url.replace("https://", "").replace("http://", "").split("/")[0]
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        self.found_subdomains = []
        print(f"Subdomain Scanner Ready! Domain: {self.domain}")

    # ============================================================
    # STEP 1 — Common subdomain wordlist
    # ============================================================
    def get_wordlist(self):
        """
        Common subdomains that companies use.
        WHY: These are the most commonly found subdomains
        in real penetration tests worldwide.
        """
        return [
            # Development and testing
            "dev", "development", "staging", "stage",
            "test", "testing", "qa", "uat", "sandbox",
            "demo", "beta", "alpha", "preview",

            # APIs and backends
            "api", "api2", "api3", "apis", "backend",
            "rest", "graphql", "gateway", "service",
            "v1", "v2", "v3", "internal",

            # Admin and management
            "admin", "administrator", "manage", "management",
            "portal", "dashboard", "console", "panel",
            "cp", "cpanel", "whm", "plesk",

            # Infrastructure
            "mail", "email", "smtp", "imap", "pop",
            "ftp", "sftp", "ssh", "vpn", "remote",
            "cdn", "static", "assets", "media", "img",
            "images", "files", "upload", "uploads",

            # Databases
            "db", "database", "mysql", "mongo", "redis",
            "elasticsearch", "kibana", "phpmyadmin",

            # Monitoring
            "monitor", "monitoring", "status", "health",
            "metrics", "logs", "logging", "grafana",
            "prometheus", "jenkins", "ci", "cd",

            # Auth
            "auth", "login", "sso", "oauth", "identity",
            "accounts", "account", "user", "users",

            # Common business
            "shop", "store", "blog", "news", "help",
            "support", "docs", "documentation", "wiki",
            "forum", "community", "chat", "app",
            "mobile", "m", "www", "web", "old",
            "new", "secure", "safe", "payment", "pay",

            # Cloud
            "s3", "bucket", "storage", "backup", "backups",
        ]

    # ============================================================
    # STEP 2 — Check if subdomain exists via DNS
    # ============================================================
    def check_subdomain_dns(self, subdomain):
        """
        Fast DNS check before making HTTP request.
        WHY: DNS check is 10x faster than HTTP request.
        If DNS fails = subdomain does not exist = skip!
        """
        full_domain = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return full_domain, ip
        except socket.gaierror:
            return None, None

    # ============================================================
    # STEP 3 — Check if subdomain responds to HTTP
    # ============================================================
    def check_subdomain_http(self, subdomain_domain, ip):
        """
        After DNS confirms subdomain exists — check HTTP response.
        WHY: DNS exists does not mean website is running.
        We need to verify what is actually there!
        """
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain_domain}"
            try:
                resp = self.session.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # Determine severity based on subdomain name
                subdomain_name = subdomain_domain.split(".")[0]
                high_risk = ["admin", "administrator", "dev", "development",
                             "staging", "test", "api", "internal", "backend",
                             "db", "database", "phpmyadmin", "jenkins", "grafana"]

                severity = "HIGH" if subdomain_name in high_risk else "MEDIUM"

                return {
                    "subdomain": subdomain_domain,
                    "ip": ip,
                    "url": url,
                    "status": resp.status_code,
                    "title": self.get_page_title(resp.text),
                    "server": resp.headers.get("Server", "Unknown"),
                    "severity": severity
                }
            except Exception:
                continue
        return None

    # ============================================================
    # STEP 4 — Extract page title
    # ============================================================
    def get_page_title(self, html):
        """Gets page title to help identify what the subdomain is."""
        try:
            import re
            match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:50]
        except Exception:
            pass
        return "No title"

    # ============================================================
    # STEP 5 — Scan one subdomain (DNS + HTTP)
    # ============================================================
    def scan_single(self, subdomain):
        """Complete check for one subdomain."""
        domain, ip = self.check_subdomain_dns(subdomain)
        if not domain:
            return None

        result = self.check_subdomain_http(domain, ip)
        if result:
            print(f"[{result['severity']}] Found: {result['url']} "
                  f"(Status: {result['status']}) — {result['title']}")
            return result
        return None

    # ============================================================
    # STEP 6 — Run full scan with threading
    # ============================================================
    def run_full_scan(self, max_workers=20):
        """
        Scans all subdomains simultaneously using threads.
        WHY: Checking 100 subdomains one by one = 500 seconds
        With 20 threads = 25 seconds! 20x faster!
        """
        print("\n" + "="*60)
        print(f"SecureScope Subdomain Scanner")
        print(f"Domain: {self.domain}")
        print("="*60)

        wordlist = self.get_wordlist()
        print(f"[*] Testing {len(wordlist)} subdomains with {max_workers} threads...")

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.scan_single, wordlist))

        # Filter out None results
        found = [r for r in results if r is not None]
        self.found_subdomains = found

        # Convert to findings format
        for sub in found:
            self.findings.append({
                "type": "Subdomain Discovered",
                "detail": f"Active subdomain found: {sub['url']} — {sub['title']}",
                "severity": sub["severity"],
                "evidence": f"IP: {sub['ip']} | Status: {sub['status']} | Server: {sub['server']}",
                "url": sub["url"]
            })

        print("\n" + "="*60)
        print(f"Subdomain Scan Complete!")
        print(f"Found: {len(found)} active subdomains")

        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        print(f"HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = SubdomainScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DISCOVERED SUBDOMAINS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f['evidence']}")
        print(f"  URL     : {f['url']}")