"""
SecureScope Compliance Reporter
=================================
Maps security findings to compliance frameworks.

WHY THIS IS VALUABLE:
Banks, fintech, healthcare companies MUST
comply with regulations.

Failing compliance audit = 
- Cannot process payments (PCI-DSS)
- Massive fines (GDPR)
- License revocation (healthcare)

Companies pay ₹1-5 lakhs for compliance audits!
Our tool does it automatically!

Frameworks covered:
1. PCI-DSS v4.0 (Payment Card Industry)
2. ISO 27001:2022 (Information Security)
3. OWASP Top 10 2021 (Web Security)
4. GDPR (Data Protection)
5. CERT-In Guidelines (India Specific!)
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse


class ComplianceReporter:
    def __init__(self, target_url, company_name="Target Organization"):
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.company = company_name
        self.report_date = datetime.now().strftime("%B %d, %Y")
        self.findings = []
        self.compliance_results = {}

        # Create output directory
        os.makedirs("compliance_reports", exist_ok=True)
        print(f"Compliance Reporter Ready!")
        print(f"Target: {self.target}")
        print(f"Company: {self.company}")

    # ============================================================
    # PCI-DSS v4.0 Mapping
    # ============================================================
    def get_pcidss_mapping(self):
        """
        Maps vulnerabilities to PCI-DSS v4.0 requirements.

        PCI-DSS = Payment Card Industry Data Security Standard
        Any company processing credit cards MUST comply!

        12 Main Requirements:
        Req 1-2:  Network Security
        Req 3-4:  Data Protection
        Req 5-6:  Vulnerability Management
        Req 7-8:  Access Control
        Req 9:    Physical Security
        Req 10:   Logging & Monitoring
        Req 11:   Security Testing ← Our scanner does this!
        Req 12:   Security Policy
        """
        return {
            "SQL Injection": {
                "requirement": "6.3.2",
                "title": "Protect web-facing applications against attacks",
                "description": "SQL injection vulnerabilities must be addressed",
                "severity": "Critical",
                "deadline": "Immediate"
            },
            "Cross-Site Scripting XSS": {
                "requirement": "6.3.2",
                "title": "Protect web-facing applications",
                "description": "XSS vulnerabilities allow script injection",
                "severity": "High",
                "deadline": "30 days"
            },
            "Missing Security Header": {
                "requirement": "6.3.2",
                "title": "Web application security controls",
                "description": "Security headers protect against common attacks",
                "severity": "Medium",
                "deadline": "30 days"
            },
            "SSL Certificate Expired": {
                "requirement": "4.2.1",
                "title": "Strong cryptography for data transmission",
                "description": "Expired certificates compromise data security",
                "severity": "Critical",
                "deadline": "Immediate"
            },
            "Weak TLS Version": {
                "requirement": "4.2.1",
                "title": "Strong cryptography protocols required",
                "description": "TLS 1.0/1.1 are deprecated and insecure",
                "severity": "High",
                "deadline": "30 days"
            },
            "Exposed Admin Panel": {
                "requirement": "7.2.1",
                "title": "Restrict access to system components",
                "description": "Admin panels must be restricted to authorized users",
                "severity": "High",
                "deadline": "Immediate"
            },
            "No Rate Limiting": {
                "requirement": "8.3.4",
                "title": "Account lockout mechanisms",
                "description": "Brute force protection required",
                "severity": "High",
                "deadline": "30 days"
            },
            "Sensitive File Exposed": {
                "requirement": "3.3.1",
                "title": "Protect stored sensitive data",
                "description": "Sensitive files must not be publicly accessible",
                "severity": "Critical",
                "deadline": "Immediate"
            },
            "Missing HSTS": {
                "requirement": "4.2.1",
                "title": "Strong cryptography for transmissions",
                "description": "HSTS prevents SSL stripping attacks",
                "severity": "Medium",
                "deadline": "30 days"
            },
            "CORS Misconfiguration": {
                "requirement": "6.3.2",
                "title": "Web application security",
                "description": "CORS must be properly configured",
                "severity": "High",
                "deadline": "30 days"
            },
            "JWT Weak Secret": {
                "requirement": "8.3.2",
                "title": "Strong cryptography for authentication",
                "description": "Authentication tokens must use strong secrets",
                "severity": "Critical",
                "deadline": "Immediate"
            },
            "SSRF Vulnerability": {
                "requirement": "6.3.2",
                "title": "Protect against server-side attacks",
                "description": "SSRF can expose internal network and credentials",
                "severity": "Critical",
                "deadline": "Immediate"
            },
            "Public S3 Bucket": {
                "requirement": "3.3.1",
                "title": "Protect stored cardholder data",
                "description": "Cloud storage must not be publicly accessible",
                "severity": "Critical",
                "deadline": "Immediate"
            },
        }

    # ============================================================
    # ISO 27001:2022 Mapping
    # ============================================================
    def get_iso27001_mapping(self):
        """
        Maps vulnerabilities to ISO 27001:2022 controls.

        ISO 27001 = International Information Security Standard
        Large enterprises need this certification.
        Audited by certified auditors annually.

        Controls organized in Annex A:
        A.5  = Organizational Controls
        A.6  = People Controls
        A.7  = Physical Controls
        A.8  = Technological Controls ← Most relevant
        """
        return {
            "SQL Injection": {
                "control": "A.8.28",
                "title": "Secure coding",
                "description": "Injection flaws addressed in secure coding practices",
                "domain": "Technological Controls"
            },
            "Cross-Site Scripting XSS": {
                "control": "A.8.28",
                "title": "Secure coding",
                "description": "XSS addressed through input validation",
                "domain": "Technological Controls"
            },
            "Missing Security Header": {
                "control": "A.8.23",
                "title": "Web filtering",
                "description": "Security headers implement web filtering",
                "domain": "Technological Controls"
            },
            "SSL Certificate Expired": {
                "control": "A.8.24",
                "title": "Use of cryptography",
                "description": "Valid certificates required for cryptography",
                "domain": "Technological Controls"
            },
            "Weak TLS Version": {
                "control": "A.8.24",
                "title": "Use of cryptography",
                "description": "Strong cryptographic protocols required",
                "domain": "Technological Controls"
            },
            "Exposed Admin Panel": {
                "control": "A.8.2",
                "title": "Privileged access rights",
                "description": "Admin access must be controlled and monitored",
                "domain": "Technological Controls"
            },
            "No Rate Limiting": {
                "control": "A.8.5",
                "title": "Secure authentication",
                "description": "Authentication must include brute force protection",
                "domain": "Technological Controls"
            },
            "Sensitive File Exposed": {
                "control": "A.8.10",
                "title": "Information deletion",
                "description": "Sensitive information must be properly protected",
                "domain": "Technological Controls"
            },
            "SSRF Vulnerability": {
                "control": "A.8.28",
                "title": "Secure coding",
                "description": "SSRF addressed through input validation",
                "domain": "Technological Controls"
            },
            "Public S3 Bucket": {
                "control": "A.8.10",
                "title": "Information deletion and protection",
                "description": "Cloud storage access must be controlled",
                "domain": "Technological Controls"
            },
            "Missing DMARC Record": {
                "control": "A.8.23",
                "title": "Web filtering",
                "description": "Email security controls required",
                "domain": "Technological Controls"
            },
            "CORS Misconfiguration": {
                "control": "A.8.23",
                "title": "Web filtering",
                "description": "Cross-origin requests must be controlled",
                "domain": "Technological Controls"
            },
        }

    # ============================================================
    # OWASP Top 10 2021 Mapping
    # ============================================================
    def get_owasp_mapping(self):
        """
        Maps vulnerabilities to OWASP Top 10 2021.

        Most recognized web security standard!
        Every security professional knows OWASP.
        Bug bounty programs reference OWASP constantly.
        """
        return {
            "SQL Injection": {
                "category": "A03:2021",
                "title": "Injection",
                "description": "SQL injection is the most classic injection attack",
                "rank": 3
            },
            "Cross-Site Scripting XSS": {
                "category": "A03:2021",
                "title": "Injection",
                "description": "XSS is a form of injection attack",
                "rank": 3
            },
            "Exposed Admin Panel": {
                "category": "A01:2021",
                "title": "Broken Access Control",
                "description": "Admin panels must have proper access control",
                "rank": 1
            },
            "IDOR Vulnerability": {
                "category": "A01:2021",
                "title": "Broken Access Control",
                "description": "IDOR is most common access control failure",
                "rank": 1
            },
            "JWT Weak Secret": {
                "category": "A02:2021",
                "title": "Cryptographic Failures",
                "description": "Weak JWT secrets are cryptographic failures",
                "rank": 2
            },
            "SSL Certificate Expired": {
                "category": "A02:2021",
                "title": "Cryptographic Failures",
                "description": "Expired certificates are cryptographic failures",
                "rank": 2
            },
            "Missing Security Header": {
                "category": "A05:2021",
                "title": "Security Misconfiguration",
                "description": "Missing headers are security misconfigurations",
                "rank": 5
            },
            "SSRF Vulnerability": {
                "category": "A10:2021",
                "title": "Server-Side Request Forgery",
                "description": "SSRF is now in OWASP Top 10!",
                "rank": 10
            },
            "Sensitive File Exposed": {
                "category": "A05:2021",
                "title": "Security Misconfiguration",
                "description": "Exposed files are security misconfigurations",
                "rank": 5
            },
            "Outdated Library": {
                "category": "A06:2021",
                "title": "Vulnerable and Outdated Components",
                "description": "Outdated libraries with known vulnerabilities",
                "rank": 6
            },
            "CORS Misconfiguration": {
                "category": "A05:2021",
                "title": "Security Misconfiguration",
                "description": "CORS misconfiguration is security misconfiguration",
                "rank": 5
            },
            "Prompt Injection": {
                "category": "A03:2021",
                "title": "Injection",
                "description": "Prompt injection is a new form of injection",
                "rank": 3
            },
        }

    # ============================================================
    # GDPR Mapping
    # ============================================================
    def get_gdpr_mapping(self):
        """
        Maps vulnerabilities to GDPR Articles.

        GDPR = General Data Protection Regulation
        Applies to ANY company handling EU citizen data!
        Fines: Up to 4% of global revenue or €20 million!

        Indian companies serving EU customers must comply!
        """
        return {
            "SQL Injection": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Must implement appropriate technical measures",
                "fine_risk": "Up to 4% global turnover"
            },
            "Sensitive File Exposed": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Personal data must be protected from unauthorized access",
                "fine_risk": "Up to 4% global turnover"
            },
            "IDOR Vulnerability": {
                "article": "Article 25",
                "title": "Data protection by design",
                "description": "Access control must prevent unauthorized data access",
                "fine_risk": "Up to 2% global turnover"
            },
            "Missing Security Header": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Technical measures must protect personal data",
                "fine_risk": "Up to 2% global turnover"
            },
            "SSL Certificate Expired": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Encryption required for personal data in transit",
                "fine_risk": "Up to 4% global turnover"
            },
            "Public S3 Bucket": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Personal data must not be publicly accessible",
                "fine_risk": "Up to 4% global turnover"
            },
            "No Rate Limiting": {
                "article": "Article 32",
                "title": "Security of processing",
                "description": "Must protect against unauthorized access attempts",
                "fine_risk": "Up to 2% global turnover"
            },
        }

    # ============================================================
    # CERT-In Guidelines (India Specific!)
    # ============================================================
    def get_certin_mapping(self):
        """
        Maps to CERT-In (Indian Computer Emergency Response Team) guidelines.

        WHY UNIQUE:
        Most tools only cover international standards!
        We cover INDIA SPECIFIC regulations!

        CERT-In guidelines mandatory for:
        - Banks and financial institutions
        - Government websites
        - Critical infrastructure
        - ISPs and telecom companies

        New CERT-In rules 2022:
        - Report incidents within 6 hours!
        - Maintain logs for 180 days
        - Mandatory vulnerability disclosure
        """
        return {
            "SQL Injection": {
                "guideline": "CERT-In Advisory 2023",
                "title": "Web Application Security",
                "description": "Critical vulnerabilities must be reported to CERT-In",
                "reporting_required": True,
                "deadline": "6 hours for critical incidents"
            },
            "Missing Security Header": {
                "guideline": "CERT-In Web Security Guidelines",
                "title": "HTTP Security Headers",
                "description": "Security headers recommended by CERT-In",
                "reporting_required": False,
                "deadline": "30 days"
            },
            "SSL Certificate Expired": {
                "guideline": "CERT-In Crypto Guidelines",
                "title": "Cryptographic Standards",
                "description": "Valid SSL/TLS certificates mandatory",
                "reporting_required": False,
                "deadline": "Immediate"
            },
            "Exposed Admin Panel": {
                "guideline": "CERT-In Access Control Guidelines",
                "title": "Administrative Access Control",
                "description": "Admin panels must be secured and monitored",
                "reporting_required": False,
                "deadline": "Immediate"
            },
            "SSRF Vulnerability": {
                "guideline": "CERT-In Advisory 2023",
                "title": "Server-Side Request Forgery",
                "description": "SSRF vulnerabilities must be patched immediately",
                "reporting_required": True,
                "deadline": "6 hours if exploited"
            },
            "Public S3 Bucket": {
                "guideline": "CERT-In Cloud Security Guidelines",
                "title": "Cloud Storage Security",
                "description": "Public cloud storage containing sensitive data",
                "reporting_required": True,
                "deadline": "6 hours if data breach"
            },
        }

    # ============================================================
    # Map Findings to All Frameworks
    # ============================================================
    def map_findings(self, scan_findings):
        """
        Maps all scan findings to compliance frameworks.
        """
        print("[*] Mapping findings to compliance frameworks...")

        pcidss = self.get_pcidss_mapping()
        iso27001 = self.get_iso27001_mapping()
        owasp = self.get_owasp_mapping()
        gdpr = self.get_gdpr_mapping()
        certin = self.get_certin_mapping()

        mapped_findings = []

        for finding in scan_findings:
            vuln_type = finding.get("type", "")
            severity = finding.get("severity", "MEDIUM")

            # Find best match in each framework
            def find_best_match(mapping, vuln_type):
                for key in mapping:
                    if key.lower() in vuln_type.lower() or \
                       vuln_type.lower() in key.lower():
                        return mapping[key]
                return None

            mapped = {
                "finding": finding,
                "compliance": {
                    "pci_dss": find_best_match(pcidss, vuln_type),
                    "iso_27001": find_best_match(iso27001, vuln_type),
                    "owasp": find_best_match(owasp, vuln_type),
                    "gdpr": find_best_match(gdpr, vuln_type),
                    "cert_in": find_best_match(certin, vuln_type),
                }
            }

            mapped_findings.append(mapped)
            self.findings.append(mapped)

        print(f"[+] Mapped {len(mapped_findings)} findings to compliance frameworks")
        return mapped_findings

    # ============================================================
    # Calculate Compliance Score
    # ============================================================
    def calculate_compliance_score(self):
        """
        Calculates compliance score for each framework.
        Shows overall compliance percentage!
        """
        scores = {
            "PCI-DSS": 100,
            "ISO-27001": 100,
            "OWASP": 100,
            "GDPR": 100,
            "CERT-In": 100
        }

        for mapped in self.findings:
            finding = mapped["finding"]
            severity = finding.get("severity", "LOW")
            compliance = mapped["compliance"]

            # Deduct points based on severity
            deduction = {
                "CRITICAL": 25,
                "HIGH": 15,
                "MEDIUM": 8,
                "LOW": 3
            }.get(severity, 3)

            if compliance["pci_dss"]:
                scores["PCI-DSS"] = max(0, scores["PCI-DSS"] - deduction)
            if compliance["iso_27001"]:
                scores["ISO-27001"] = max(0, scores["ISO-27001"] - deduction)
            if compliance["owasp"]:
                scores["OWASP"] = max(0, scores["OWASP"] - deduction)
            if compliance["gdpr"]:
                scores["GDPR"] = max(0, scores["GDPR"] - deduction)
            if compliance["cert_in"]:
                scores["CERT-In"] = max(0, scores["CERT-In"] - deduction)

        return scores

    # ============================================================
    # Generate Compliance Report
    # ============================================================
    def generate_report(self, scan_findings):
        """
        Generates complete compliance report.
        """
        print("\n" + "="*60)
        print("SecureScope Compliance Reporter")
        print("PCI-DSS | ISO 27001 | OWASP | GDPR | CERT-In")
        print("="*60)

        # Map findings
        self.map_findings(scan_findings)

        # Calculate scores
        scores = self.calculate_compliance_score()

        # Build report
        report = {
            "target": self.target,
            "company": self.company,
            "report_date": self.report_date,
            "compliance_scores": scores,
            "total_findings": len(self.findings),
            "mapped_findings": self.findings,
            "summary": self.generate_summary(scores),
        }

        # Save reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"compliance_reports/compliance_{self.domain}_{timestamp}"

        # JSON report
        with open(f"{base}.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

        # Text report
        # Text report
        with open(f"{base}.txt", "w", encoding="utf-8") as f:
            f.write(self.generate_text_report(scores))

        print(f"\n[+] Reports saved to compliance_reports/")
        print(f"\n--- COMPLIANCE SCORES ---")
        for framework, score in scores.items():
            status = "✅ PASS" if score >= 70 else "❌ FAIL"
            print(f"  {framework}: {score}/100 {status}")

        return report

    def generate_summary(self, scores):
        """Generates executive summary for compliance."""
        failed = [f for f, s in scores.items() if s < 70]
        passed = [f for f, s in scores.items() if s >= 70]

        summary = f"""
COMPLIANCE EXECUTIVE SUMMARY
Target: {self.target}
Company: {self.company}
Date: {self.report_date}

PASSED: {', '.join(passed) if passed else 'None'}
FAILED: {', '.join(failed) if failed else 'None'}

Total Findings: {len(self.findings)}
Critical Issues: {sum(1 for f in self.findings if f['finding'].get('severity') == 'CRITICAL')}

IMMEDIATE ACTIONS REQUIRED:
"""
        for mapped in self.findings:
            f = mapped["finding"]
            if f.get("severity") == "CRITICAL":
                summary += f"- Fix: {f.get('type', 'Unknown')} at {f.get('url', '')}\n"

        return summary

    def generate_text_report(self, scores):
        """Generates detailed text compliance report."""
        lines = []
        lines.append("=" * 70)
        lines.append("COMPLIANCE ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"Company: {self.company}")
        lines.append(f"Target: {self.target}")
        lines.append(f"Date: {self.report_date}")
        lines.append("")

        lines.append("COMPLIANCE SCORES")
        lines.append("-" * 40)
        for framework, score in scores.items():
            status = "PASS" if score >= 70 else "FAIL"
            lines.append(f"{framework}: {score}/100 — {status}")
        lines.append("")

        lines.append("DETAILED FINDINGS WITH COMPLIANCE MAPPING")
        lines.append("-" * 40)

        for i, mapped in enumerate(self.findings, 1):
            f = mapped["finding"]
            compliance = mapped["compliance"]

            lines.append(f"\n[{i}] {f.get('type', 'Unknown')}")
            lines.append(f"Severity: {f.get('severity', 'MEDIUM')}")
            lines.append(f"URL: {f.get('url', 'N/A')}")
            lines.append("")

            if compliance["pci_dss"]:
                pci = compliance["pci_dss"]
                lines.append(f"PCI-DSS: Requirement {pci['requirement']} — {pci['title']}")
                lines.append(f"         Deadline: {pci['deadline']}")

            if compliance["iso_27001"]:
                iso = compliance["iso_27001"]
                lines.append(f"ISO 27001: Control {iso['control']} — {iso['title']}")

            if compliance["owasp"]:
                owasp = compliance["owasp"]
                lines.append(f"OWASP: {owasp['category']} — {owasp['title']}")

            if compliance["gdpr"]:
                gdpr = compliance["gdpr"]
                lines.append(f"GDPR: {gdpr['article']} — {gdpr['title']}")
                lines.append(f"      Fine Risk: {gdpr['fine_risk']}")

            if compliance["cert_in"]:
                certin = compliance["cert_in"]
                lines.append(f"CERT-In: {certin['guideline']}")
                if certin.get("reporting_required"):
                    lines.append(f"         [!] REPORTING REQUIRED TO CERT-In!")
            lines.append("")

        lines.append("=" * 70)
        lines.append("END OF COMPLIANCE REPORT")
        lines.append(f"Generated by SecureScope — {self.report_date}")
        lines.append("=" * 70)

        return "\n".join(lines)


if __name__ == "__main__":
    reporter = ComplianceReporter(
        "https://sharpener.tech",
        "Sharpener Tech Private Limited"
    )

    # Test with sample findings
    test_findings = [
        {
            "type": "Missing Security Header",
            "severity": "MEDIUM",
            "url": "https://sharpener.tech",
            "detail": "X-Frame-Options missing"
        },
        {
            "type": "SSL Certificate Expired",
            "severity": "CRITICAL",
            "url": "https://sharpener.tech",
            "detail": "Certificate expired"
        },
        {
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "url": "https://sharpener.tech/search",
            "detail": "SQL injection in search"
        },
        {
            "type": "SSRF Vulnerability",
            "severity": "CRITICAL",
            "url": "https://sharpener.tech/fetch",
            "detail": "SSRF via url parameter"
        },
        {
            "type": "Public S3 Bucket",
            "severity": "CRITICAL",
            "url": "https://sharpener.s3.amazonaws.com",
            "detail": "Bucket publicly accessible"
        }
    ]

    report = reporter.generate_report(test_findings)

    print("\n--- COMPLIANCE SUMMARY ---")
    print(report["summary"])