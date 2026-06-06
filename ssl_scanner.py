import ssl
import socket
import datetime
import requests
import json
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSLScanner:
    def __init__(self, target_url):
        parsed = urlparse(target_url)
        self.target = target_url
        self.hostname = parsed.netloc or target_url.replace(
            "https://", "").replace("http://", "").split("/")[0]
        self.port = 443
        self.findings = []
        self.cert_info = {}
        print(f"SSL Scanner Ready! Target: {self.hostname}")

    # ============================================================
    # STEP 1 — Get SSL Certificate Information
    # ============================================================
    def get_certificate(self):
        """
        Retrieves SSL certificate details.
        WHY: Certificate contains critical security info —
        expiry, issuer, subject, and supported algorithms.
        """
        print("[*] Retrieving SSL certificate...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.hostname, self.port), timeout=10
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.hostname
                ) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self.cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "san": cert.get("subjectAltName", []),
                        "cipher": cipher,
                        "version": version
                    }

                    print(f"[+] Certificate retrieved successfully!")
                    print(f"[+] TLS Version: {version}")
                    print(f"[+] Cipher: {cipher[0] if cipher else 'Unknown'}")
                    return True

        except ssl.SSLError as e:
            self.findings.append({
                "type": "SSL Connection Error",
                "detail": f"SSL error: {str(e)[:100]}",
                "severity": "CRITICAL",
                "evidence": str(e)[:100],
                "url": self.target
            })
            print(f"[CRITICAL] SSL error: {e}")
            return False

        except Exception as e:
            print(f"[!] Certificate retrieval error: {e}")
            return False

    # ============================================================
    # STEP 2 — Check Certificate Expiry
    # ============================================================
    def check_expiry(self):
        """
        Checks if certificate is expired or expiring soon.
        WHY: Expired certificate = browser security warning
        Users see warning = they leave = business loss!
        Also expired cert = attacker can get same domain cert
        and intercept traffic!
        """
        print("[*] Checking certificate expiry...")
        if not self.cert_info:
            return

        try:
            not_after = self.cert_info.get("not_after", "")
            if not not_after:
                return

            expire_date = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            )
            now = datetime.datetime.utcnow()
            days_left = (expire_date - now).days

            print(f"[*] Certificate expires: {not_after}")
            print(f"[*] Days remaining: {days_left}")

            if days_left < 0:
                self.findings.append({
                    "type": "SSL Certificate Expired",
                    "detail": f"Certificate EXPIRED {abs(days_left)} days ago!",
                    "severity": "CRITICAL",
                    "evidence": f"Expired: {not_after}",
                    "url": self.target
                })
                print(f"[CRITICAL] Certificate EXPIRED!")

            elif days_left < 14:
                self.findings.append({
                    "type": "SSL Certificate Expiring Very Soon",
                    "detail": f"Certificate expires in {days_left} days — URGENT!",
                    "severity": "CRITICAL",
                    "evidence": f"Expires: {not_after}",
                    "url": self.target
                })
                print(f"[CRITICAL] Certificate expiring in {days_left} days!")

            elif days_left < 30:
                self.findings.append({
                    "type": "SSL Certificate Expiring Soon",
                    "detail": f"Certificate expires in {days_left} days",
                    "severity": "HIGH",
                    "evidence": f"Expires: {not_after}",
                    "url": self.target
                })
                print(f"[HIGH] Certificate expiring in {days_left} days!")

            elif days_left < 90:
                self.findings.append({
                    "type": "SSL Certificate Expiring",
                    "detail": f"Certificate expires in {days_left} days — plan renewal",
                    "severity": "MEDIUM",
                    "evidence": f"Expires: {not_after}",
                    "url": self.target
                })
                print(f"[MEDIUM] Certificate expiring in {days_left} days")

            else:
                print(f"[+] Certificate valid for {days_left} more days — OK!")

        except Exception as e:
            print(f"[!] Expiry check error: {e}")

    # ============================================================
    # STEP 3 — Check TLS Version
    # ============================================================
    def check_tls_version(self):
        """
        Checks which TLS versions are supported.
        WHY:
        TLS 1.0 (2000) = POODLE, BEAST attacks — crackable!
        TLS 1.1 (2006) = deprecated — known weaknesses
        TLS 1.2 (2008) = acceptable but aging
        TLS 1.3 (2018) = most secure — recommended!
        """
        print("[*] Checking TLS versions...")

        tls_versions = [
            (ssl.PROTOCOL_TLS_CLIENT, "TLS"),
        ]

        # Test old TLS versions
        old_versions = [
            ("TLSv1", "TLS 1.0"),
            ("TLSv1.1", "TLS 1.1"),
        ]

        for version_name, display_name in old_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1

                with socket.create_connection(
                    (self.hostname, self.port), timeout=5
                ) as sock:
                    with context.wrap_socket(sock) as ssock:
                        self.findings.append({
                            "type": f"Weak TLS Version Supported",
                            "detail": f"Server accepts {display_name} — deprecated and vulnerable",
                            "severity": "HIGH",
                            "evidence": f"{display_name} connection successful",
                            "url": self.target
                        })
                        print(f"[HIGH] {display_name} supported — vulnerable!")

            except ssl.SSLError:
                print(f"[+] {display_name} rejected — good!")
            except Exception:
                print(f"[+] {display_name} not supported — good!")

        # Check current version
        version = self.cert_info.get("version", "")
        if version:
            if version in ["TLSv1", "TLSv1.1"]:
                print(f"[HIGH] Currently using weak {version}!")
            elif version == "TLSv1.2":
                print(f"[MEDIUM] Using TLS 1.2 — consider upgrading to 1.3")
            elif version == "TLSv1.3":
                print(f"[+] Using TLS 1.3 — excellent!")

    # ============================================================
    # STEP 4 — Check Cipher Suites
    # ============================================================
    def check_cipher_strength(self):
        """
        Checks if weak cipher suites are used.
        WHY: Weak ciphers = attacker can decrypt your HTTPS traffic!
        Like having a lock but the key is easy to copy.
        RC4, DES, 3DES = broken algorithms = traffic readable!
        """
        print("[*] Checking cipher suite strength...")

        if not self.cert_info.get("cipher"):
            return

        cipher = self.cert_info["cipher"]
        cipher_name = cipher[0] if cipher else ""
        cipher_bits = cipher[2] if len(cipher) > 2 else 0

        print(f"[*] Cipher: {cipher_name} ({cipher_bits} bits)")

        weak_ciphers = [
            "RC4", "DES", "3DES", "MD5", "NULL",
            "EXPORT", "ANON", "ADH", "AECDH"
        ]

        if any(weak in cipher_name.upper() for weak in weak_ciphers):
            self.findings.append({
                "type": "Weak Cipher Suite",
                "detail": f"Weak cipher in use: {cipher_name}",
                "severity": "HIGH",
                "evidence": f"Cipher: {cipher_name} | Bits: {cipher_bits}",
                "url": self.target
            })
            print(f"[HIGH] Weak cipher: {cipher_name}")

        elif cipher_bits and cipher_bits < 128:
            self.findings.append({
                "type": "Insufficient Cipher Key Length",
                "detail": f"Cipher key length too short: {cipher_bits} bits",
                "severity": "HIGH",
                "evidence": f"Key length: {cipher_bits} bits (minimum: 128)",
                "url": self.target
            })
            print(f"[HIGH] Weak key length: {cipher_bits} bits!")

        else:
            print(f"[+] Cipher strength OK: {cipher_name} ({cipher_bits} bits)")

    # ============================================================
    # STEP 5 — Check Certificate Transparency Logs
    # ============================================================
    def check_certificate_transparency(self):
        """
        Queries Certificate Transparency logs for this domain.
        WHY: All SSL certificates are publicly logged!
        This reveals ALL subdomains that EVER had a certificate —
        including forgotten development and staging servers!
        Hackers use this to find hidden attack surface.
        """
        print("[*] Checking Certificate Transparency logs...")

        try:
            # Query crt.sh — free CT log search
            url = f"https://crt.sh/?q=%.{self.hostname}&output=json"
            resp = requests.get(url, timeout=15)

            if resp.status_code == 200:
                certs = resp.json()

                # Extract unique subdomains
                subdomains = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if subdomain and not subdomain.startswith("*"):
                            subdomains.add(subdomain)

                print(f"[+] Found {len(subdomains)} subdomains in CT logs!")

                # Flag interesting subdomains
                high_risk_keywords = [
                    "admin", "dev", "development", "staging",
                    "test", "internal", "backend", "api",
                    "jenkins", "grafana", "kibana", "db"
                ]

                for subdomain in subdomains:
                    subdomain_part = subdomain.split(".")[0]
                    if any(kw in subdomain_part.lower() for kw in high_risk_keywords):
                        self.findings.append({
                            "type": "Sensitive Subdomain in CT Logs",
                            "detail": f"High-risk subdomain found in certificate logs: {subdomain}",
                            "severity": "MEDIUM",
                            "evidence": f"Found in crt.sh CT logs",
                            "url": f"https://{subdomain}"
                        })
                        print(f"[MEDIUM] Interesting subdomain: {subdomain}")

        except Exception as e:
            print(f"[!] CT log check error: {e}")

    # ============================================================
    # STEP 6 — Check HSTS Header
    # ============================================================
    def check_hsts(self):
        """
        Checks if HTTP Strict Transport Security is configured.
        WHY: Without HSTS, attacker can downgrade HTTPS to HTTP
        and intercept all traffic — even after user visited HTTPS!
        HSTS tells browser: ALWAYS use HTTPS for this domain.
        """
        print("[*] Checking HSTS configuration...")

        try:
            resp = requests.get(
                self.target, timeout=10, verify=False
            )
            hsts = resp.headers.get("Strict-Transport-Security", "")

            if not hsts:
                self.findings.append({
                    "type": "Missing HSTS Header",
                    "detail": "Strict-Transport-Security header missing — SSL stripping attack possible",
                    "severity": "MEDIUM",
                    "evidence": "No HSTS header in response",
                    "url": self.target
                })
                print("[MEDIUM] HSTS missing!")

            else:
                print(f"[+] HSTS present: {hsts}")

                # Check max-age
                if "max-age" in hsts.lower():
                    try:
                        max_age = int(hsts.lower().split("max-age=")[1].split(";")[0])
                        if max_age < 31536000:  # Less than 1 year
                            self.findings.append({
                                "type": "HSTS Max-Age Too Short",
                                "detail": f"HSTS max-age is only {max_age} seconds — should be at least 1 year",
                                "severity": "LOW",
                                "evidence": f"max-age={max_age}",
                                "url": self.target
                            })
                            print(f"[LOW] HSTS max-age too short: {max_age}s")
                        else:
                            print(f"[+] HSTS max-age OK: {max_age}s")
                    except Exception:
                        pass

                # Check includeSubDomains
                if "includesubdomains" not in hsts.lower():
                    self.findings.append({
                        "type": "HSTS Missing includeSubDomains",
                        "detail": "HSTS does not include subdomains — subdomain attacks possible",
                        "severity": "LOW",
                        "evidence": f"HSTS: {hsts}",
                        "url": self.target
                    })
                    print("[LOW] HSTS missing includeSubDomains")

        except Exception as e:
            print(f"[!] HSTS check error: {e}")

    # ============================================================
    # STEP 7 — Check Self Signed Certificate
    # ============================================================
    def check_self_signed(self):
        """
        Checks if certificate is self-signed.
        WHY: Self-signed = anyone can create same cert!
        Attacker creates self-signed cert for your domain
        Performs man-in-the-middle attack
        Users get security warning but may ignore it!
        """
        print("[*] Checking for self-signed certificate...")

        if not self.cert_info:
            return

        subject = self.cert_info.get("subject", {})
        issuer = self.cert_info.get("issuer", {})

        # Self-signed = issuer same as subject
        if subject == issuer:
            self.findings.append({
                "type": "Self-Signed Certificate",
                "detail": "Certificate is self-signed — not trusted by browsers!",
                "severity": "HIGH",
                "evidence": f"Subject == Issuer: {subject}",
                "url": self.target
            })
            print("[HIGH] Self-signed certificate detected!")
        else:
            issuer_org = issuer.get("organizationName", "Unknown")
            print(f"[+] Certificate issued by: {issuer_org}")

    # ============================================================
    # MAIN — Run complete SSL analysis
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope SSL/TLS Deep Scanner")
        print("="*60)

        # Get certificate first
        success = self.get_certificate()

        if success:
            self.check_expiry()
            self.check_tls_version()
            self.check_cipher_strength()
            self.check_self_signed()

        # These work independently
        self.check_hsts()
        self.check_certificate_transparency()

        print("\n" + "="*60)
        print(f"SSL Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = SSLScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")