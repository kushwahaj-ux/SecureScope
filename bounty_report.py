"""
SecureScope Bug Bounty Report Generator
=========================================
Generates professional bug bounty reports
that get ACCEPTED and paid at HIGH rates!

WHY THIS CHANGES EVERYTHING:
Same bug — basic report   = $50 or rejected
Same bug — this report    = $2000-10,000

Senior hunters spend 50% of their time
writing reports — not finding bugs!
A perfect report = perfect payout!

Covers:
1. CVSS Score Calculation
2. Professional Report Structure
3. Attack Chain Documentation
4. Business Impact Analysis
5. Evidence Documentation
6. Remediation Roadmap
7. Multiple Export Formats
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse


class BountyReport:
    def __init__(self, target_url, researcher_name="Security Researcher"):
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.researcher = researcher_name
        self.report_date = datetime.now().strftime("%B %d, %Y")
        self.findings = []
        self.chains = []

        # Create reports directory
        os.makedirs("bounty_reports", exist_ok=True)
        print(f"Bug Bounty Report Generator Ready!")
        print(f"Target: {self.target}")
        print(f"Researcher: {self.researcher}")

    # ============================================================
    # CVSS Score Calculator
    # ============================================================
    def calculate_cvss(self,
                       attack_vector="N",      # N=Network, A=Adjacent, L=Local, P=Physical
                       attack_complexity="L",   # L=Low, H=High
                       privileges_required="N", # N=None, L=Low, H=High
                       user_interaction="N",    # N=None, R=Required
                       scope="U",              # U=Unchanged, C=Changed
                       confidentiality="H",    # H=High, L=Low, N=None
                       integrity="H",          # H=High, L=Low, N=None
                       availability="N"):      # H=High, L=Low, N=None
        """
        Calculates CVSS v3.1 score professionally.

        WHY IMPORTANT:
        CVSS score determines payout tier!
        9.0-10.0 = CRITICAL = Highest payout
        7.0-8.9  = HIGH     = Good payout
        4.0-6.9  = MEDIUM   = Moderate payout
        0.1-3.9  = LOW      = Small payout

        Bug bounty programs use CVSS to
        determine exactly how much to pay!
        """

        # Base metric scores
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_scores_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scores_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        c_scores = {"H": 0.56, "L": 0.22, "N": 0.00}
        i_scores = {"H": 0.56, "L": 0.22, "N": 0.00}
        a_scores = {"H": 0.56, "L": 0.22, "N": 0.00}

        # Get scores
        av = av_scores.get(attack_vector, 0.85)
        ac = ac_scores.get(attack_complexity, 0.77)
        pr = pr_scores_c.get(privileges_required, 0.85) \
            if scope == "C" else \
            pr_scores_u.get(privileges_required, 0.85)
        ui = ui_scores.get(user_interaction, 0.85)
        c = c_scores.get(confidentiality, 0.56)
        i = i_scores.get(integrity, 0.56)
        a = a_scores.get(availability, 0.00)

        # Calculate ISS
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0
        elif scope == "U":
            base_score = min((impact + exploitability), 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        base_score = round(base_score, 1)

        # Determine severity
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        elif base_score > 0:
            severity = "LOW"
        else:
            severity = "NONE"

        # Build vector string
        vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

        return {
            "score": base_score,
            "severity": severity,
            "vector": vector
        }

    # ============================================================
    # CVSS Presets for Common Vulnerabilities
    # ============================================================
    def get_cvss_preset(self, vulnerability_type):
        """
        Returns CVSS scores for common vulnerability types.
        Based on real-world bug bounty standard scores!
        """
        presets = {
            "SQL Injection": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="U", confidentiality="H",
                integrity="H", availability="H"
            ),
            "XSS Stored": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="L", user_interaction="N",
                scope="C", confidentiality="L",
                integrity="L", availability="N"
            ),
            "XSS Reflected": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L",
                integrity="L", availability="N"
            ),
            "IDOR": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="L", user_interaction="N",
                scope="U", confidentiality="H",
                integrity="N", availability="N"
            ),
            "SSRF": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="C", confidentiality="H",
                integrity="H", availability="H"
            ),
            "Open Redirect": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L",
                integrity="L", availability="N"
            ),
            "Missing Security Header": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L",
                integrity="L", availability="N"
            ),
            "Subdomain Takeover": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="H",
                integrity="H", availability="N"
            ),
            "CORS Misconfiguration": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="U", confidentiality="H",
                integrity="H", availability="N"
            ),
            "JWT Weak Secret": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="U", confidentiality="H",
                integrity="H", availability="H"
            ),
            "Prompt Injection": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="C", confidentiality="H",
                integrity="H", availability="N"
            ),
            "Cloud Metadata SSRF": self.calculate_cvss(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="C", confidentiality="H",
                integrity="H", availability="H"
            ),
        }

        # Default for unknown types
        default = self.calculate_cvss(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="L",
            integrity="L", availability="N"
        )

        return presets.get(vulnerability_type, default)

    # ============================================================
    # OWASP and CWE Mapping
    # ============================================================
    def get_references(self, vulnerability_type):
        """
        Maps vulnerability to OWASP, CWE, and other references.
        Professional reports ALWAYS include these!
        Shows you know your stuff = more credibility = higher payout!
        """
        references = {
            "SQL Injection": {
                "owasp": "A03:2021 — Injection",
                "cwe": ["CWE-89: SQL Injection",
                        "CWE-564: SQL Injection: Hibernate"],
                "links": [
                    "https://owasp.org/Top10/A03_2021-Injection/",
                    "https://portswigger.net/web-security/sql-injection"
                ]
            },
            "XSS": {
                "owasp": "A03:2021 — Injection",
                "cwe": ["CWE-79: Cross-site Scripting"],
                "links": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting"
                ]
            },
            "IDOR": {
                "owasp": "A01:2021 — Broken Access Control",
                "cwe": ["CWE-639: Authorization Bypass Through User-Controlled Key",
                        "CWE-284: Improper Access Control"],
                "links": [
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "https://portswigger.net/web-security/access-control/idor"
                ]
            },
            "SSRF": {
                "owasp": "A10:2021 — Server-Side Request Forgery",
                "cwe": ["CWE-918: Server-Side Request Forgery"],
                "links": [
                    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                    "https://portswigger.net/web-security/ssrf"
                ]
            },
            "Open Redirect": {
                "owasp": "A01:2021 — Broken Access Control",
                "cwe": ["CWE-601: URL Redirection to Untrusted Site"],
                "links": [
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://portswigger.net/kb/issues/00500100_open-redirection"
                ]
            },
            "Subdomain Takeover": {
                "owasp": "A05:2021 — Security Misconfiguration",
                "cwe": ["CWE-284: Improper Access Control"],
                "links": [
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://hackerone.com/reports/examples"
                ]
            },
            "Prompt Injection": {
                "owasp": "OWASP LLM01:2023 — Prompt Injection",
                "cwe": ["CWE-77: Improper Neutralization of Special Elements"],
                "links": [
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "https://portswigger.net/web-security/llm-attacks"
                ]
            },
            "Missing Security Header": {
                "owasp": "A05:2021 — Security Misconfiguration",
                "cwe": ["CWE-693: Protection Mechanism Failure"],
                "links": [
                    "https://owasp.org/www-project-secure-headers/",
                    "https://securityheaders.com"
                ]
            },
        }

        # Find best match
        for vuln_key, refs in references.items():
            if vuln_key.lower() in vulnerability_type.lower():
                return refs

        # Default references
        return {
            "owasp": "OWASP Top 10",
            "cwe": ["CWE-200: Exposure of Sensitive Information"],
            "links": ["https://owasp.org/Top10/"]
        }

    # ============================================================
    # Add Finding to Report
    # ============================================================
    def add_finding(self, finding_data):
        """
        Adds a vulnerability finding to the report
        with full professional documentation.
        """
        vuln_type = finding_data.get("type", "Unknown")
        severity = finding_data.get("severity", "MEDIUM")
        url = finding_data.get("url", self.target)
        detail = finding_data.get("detail", "")
        evidence = finding_data.get("evidence", "")
        poc = finding_data.get("poc", {})
        analysis = finding_data.get("analysis", {})

        # Get CVSS score
        cvss = self.get_cvss_preset(vuln_type)

        # Get references
        refs = self.get_references(vuln_type)

        # Get payout estimate
        payout = self.estimate_payout(cvss["score"])

        # Build professional finding
        professional_finding = {
            "id": f"SS-{len(self.findings)+1:03d}",
            "title": vuln_type,
            "severity": severity,
            "cvss": cvss,
            "url": url,
            "detail": detail,
            "evidence": evidence,

            # Professional sections
            "summary": analysis.get("plain_english", detail),
            "attack_scenario": analysis.get("attack_scenario", ""),
            "business_impact": analysis.get("business_impact", ""),
            "remediation": analysis.get("immediate_fix", ""),

            # Bug bounty specific
            "references": refs,
            "poc": poc,
            "payout_estimate": payout,
            "disclosure_timeline": self.generate_timeline(),
        }

        self.findings.append(professional_finding)
        return professional_finding

    # ============================================================
    # Vulnerability Chain Documentation
    # ============================================================
    def add_vulnerability_chain(self, chain_name,
                                findings_ids, impact, payout_multiplier=3):
        """
        Documents attack chains — multiple vulnerabilities
        chained together for maximum impact!

        WHY CHAINS GET HIGHER PAYOUTS:
        Individual finding: $200
        Same findings chained: $2000+

        Chain shows REAL attack scenario!
        Programs love chains because they show
        true security impact!
        """
        chain = {
            "name": chain_name,
            "findings": findings_ids,
            "chain_description": f"Chaining {len(findings_ids)} vulnerabilities",
            "combined_impact": impact,
            "payout_estimate": f"${payout_multiplier}x individual payouts",
            "attack_flow": self.generate_attack_flow(findings_ids)
        }

        self.chains.append(chain)
        print(f"[+] Attack chain added: {chain_name}")
        return chain

    def generate_attack_flow(self, findings_ids):
        """Generates step-by-step attack flow for chain."""
        steps = []
        for i, finding_id in enumerate(findings_ids):
            # Find the finding
            finding = next(
                (f for f in self.findings if f["id"] == finding_id),
                None
            )
            if finding:
                steps.append(
                    f"Step {i+1}: Exploit {finding['title']} at {finding['url']}"
                )
        return steps

    # ============================================================
    # Payout Estimator
    # ============================================================
    def estimate_payout(self, cvss_score):
        """
        Estimates bug bounty payout based on CVSS score.
        Based on real HackerOne/Bugcrowd payout data!
        """
        if cvss_score >= 9.0:
            return {
                "range": "",
                "tier": "P1 — Critical",
                "typical": "",
                "notes": "Immediate attention required — highest priority"
            }
        elif cvss_score >= 7.0:
            return {
                "range": "",
                "tier": "P2 — High",
                "typical": "",
                "notes": "High impact — urgent fix required"
            }
        elif cvss_score >= 4.0:
            return {
                "range": "",
                "tier": "P3 — Medium",
                "typical": "",
                "notes": "Medium impact — fix within 30 days"
            }
        elif cvss_score > 0:
            return {
                "range": "",
                "tier": "P4 — Low",
                "typical": "",
                "notes": "Low impact — fix within 90 days"
            }
        else:
            return {
                "range": "",
                "tier": "P5 — Informational",
                "typical": "",
                "notes": "Informational finding"
            }

    # ============================================================
    # Disclosure Timeline
    # ============================================================
    def generate_timeline(self):
        """
        Generates responsible disclosure timeline.
        Shows professionalism — programs love this!
        """
        from datetime import timedelta
        today = datetime.now()

        return {
            "discovery_date": today.strftime("%Y-%m-%d"),
            "initial_report": today.strftime("%Y-%m-%d"),
            "expected_response": (today + timedelta(days=7)).strftime("%Y-%m-%d"),
            "expected_fix": (today + timedelta(days=30)).strftime("%Y-%m-%d"),
            "public_disclosure": (today + timedelta(days=90)).strftime("%Y-%m-%d"),
            "policy": "90-day responsible disclosure policy followed"
        }

    # ============================================================
    # Generate Professional Text Report
    # ============================================================
    def generate_text_report(self, findings=None):
        """
        Generates professional bug bounty report in text format.
        Ready to submit to HackerOne/Bugcrowd!
        """
        if findings:
            for f in findings:
                self.add_finding(f)

        report_lines = []

        # Header
        report_lines.extend([
            "=" * 70,
            "SECURITY VULNERABILITY REPORT",
            "=" * 70,
            f"Researcher: {self.researcher}",
            f"Target: {self.target}",
            f"Report Date: {self.report_date}",
            f"Total Findings: {len(self.findings)}",
            f"Attack Chains: {len(self.chains)}",
            "=" * 70,
            "",
        ])

        # Executive Summary
        critical = sum(1 for f in self.findings
                      if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings
                  if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings
                    if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings
                 if f["severity"] == "LOW")

        report_lines.extend([
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"A security assessment of {self.target} was conducted",
            f"and identified {len(self.findings)} vulnerabilities:",
            f"",
            f"  Critical: {critical}",
            f"  High:     {high}",
            f"  Medium:   {medium}",
            f"  Low:      {low}",
            "",
        ])

        # Individual Findings
        for finding in self.findings:
            report_lines.extend([
                "=" * 70,
                f"[{finding['id']}] {finding['title']}",
                "=" * 70,
                f"Severity:    {finding['severity']}",
                f"CVSS Score:  {finding['cvss']['score']} ({finding['cvss']['severity']})",
                f"CVSS Vector: {finding['cvss']['vector']}",
                f"URL:         {finding['url']}",
                f"Payout Est:  {finding['payout_estimate']['tier']} — {finding['payout_estimate']['range']}",
                "",
                "SUMMARY:",
                finding['summary'],
                "",
                "VULNERABILITY DETAILS:",
                finding['detail'],
                "",
            ])

            # Steps to reproduce from PoC
            if finding.get("poc") and finding["poc"].get("steps_to_reproduce"):
                report_lines.append("STEPS TO REPRODUCE:")
                for step in finding["poc"]["steps_to_reproduce"]:
                    report_lines.append(f"  {step}")
                report_lines.append("")

            # cURL command if available
            if finding.get("poc") and finding["poc"].get("curl_command"):
                report_lines.extend([
                    "PROOF OF CONCEPT (cURL):",
                    finding["poc"]["curl_command"],
                    "",
                ])

            # Attack scenario
            if finding.get("attack_scenario"):
                report_lines.extend([
                    "ATTACK SCENARIO:",
                    finding["attack_scenario"],
                    "",
                ])

            # Business impact
            if finding.get("business_impact"):
                report_lines.extend([
                    "BUSINESS IMPACT:",
                    finding["business_impact"],
                    "",
                ])

            # Evidence
            if finding.get("evidence"):
                report_lines.extend([
                    "EVIDENCE:",
                    finding["evidence"],
                    "",
                ])

            # Remediation
            if finding.get("remediation"):
                report_lines.extend([
                    "REMEDIATION:",
                    finding["remediation"],
                    "",
                ])

            # References
            refs = finding.get("references", {})
            if refs:
                report_lines.extend([
                    "REFERENCES:",
                    f"  OWASP: {refs.get('owasp', 'N/A')}",
                ])
                for cwe in refs.get("cwe", []):
                    report_lines.append(f"  CWE: {cwe}")
                for link in refs.get("links", [])[:2]:
                    report_lines.append(f"  Link: {link}")
                report_lines.append("")

            # Disclosure timeline
            timeline = finding.get("disclosure_timeline", {})
            if timeline:
                report_lines.extend([
                    "DISCLOSURE TIMELINE:",
                    f"  Discovery:    {timeline.get('discovery_date')}",
                    f"  Reported:     {timeline.get('initial_report')}",
                    f"  Fix Expected: {timeline.get('expected_fix')}",
                    f"  Public Disc:  {timeline.get('public_disclosure')}",
                    "",
                ])

        # Attack Chains Section
        if self.chains:
            report_lines.extend([
                "=" * 70,
                "VULNERABILITY CHAINS",
                "=" * 70,
            ])
            for chain in self.chains:
                report_lines.extend([
                    f"Chain: {chain['name']}",
                    f"Impact: {chain['combined_impact']}",
                    f"Payout Multiplier: {chain['payout_estimate']}",
                    "Attack Flow:",
                ])
                for step in chain.get("attack_flow", []):
                    report_lines.append(f"  → {step}")
                report_lines.append("")

        # Footer
        report_lines.extend([
            "=" * 70,
            "END OF REPORT",
            f"Generated by SecureScope — {self.report_date}",
            "=" * 70,
        ])

        return "\n".join(report_lines)

    # ============================================================
    # Export Report
    # ============================================================
    def export_report(self, findings=None, format="all"):
        """
        Exports report in multiple formats.
        Text format for HackerOne submission.
        JSON format for data processing.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"bounty_reports/report_{self.domain}_{timestamp}"

        files_created = []

        # Generate text report
        text_report = self.generate_text_report(findings)

        # Save text report
        txt_file = f"{base_filename}.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(text_report)
        files_created.append(txt_file)
        print(f"[+] Text report saved: {txt_file}")

        # Save JSON report
        json_file = f"{base_filename}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.target,
                "researcher": self.researcher,
                "report_date": self.report_date,
                "total_findings": len(self.findings),
                "findings": self.findings,
                "chains": self.chains,
            }, f, indent=2, default=str)
        files_created.append(json_file)
        print(f"[+] JSON report saved: {json_file}")

        # Save HackerOne ready markdown
        md_file = f"{base_filename}.md"
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(self.generate_markdown_report())
        files_created.append(md_file)
        print(f"[+] Markdown report saved: {md_file}")

        return files_created

    # ============================================================
    # Generate Markdown Report (HackerOne Format)
    # ============================================================
    def generate_markdown_report(self):
        """
        Generates HackerOne-ready markdown report.
        HackerOne uses markdown for report formatting!
        """
        md = []

        md.append(f"# Security Vulnerability Report")
        md.append(f"**Target:** {self.target}")
        md.append(f"**Date:** {self.report_date}")
        md.append(f"**Researcher:** {self.researcher}")
        md.append("")

        for finding in self.findings:
            md.append(f"## {finding['id']}: {finding['title']}")
            md.append("")
            md.append(f"**Severity:** {finding['severity']}")
            md.append(f"**CVSS Score:** {finding['cvss']['score']}")
            md.append(f"**CVSS Vector:** `{finding['cvss']['vector']}`")
            md.append(f"**Estimated Payout:** {finding['payout_estimate']['range']}")
            md.append("")

            md.append("### Summary")
            md.append(finding['summary'])
            md.append("")

            md.append("### Vulnerability Details")
            md.append(finding['detail'])
            md.append("")

            if finding.get("poc") and \
               finding["poc"].get("steps_to_reproduce"):
                md.append("### Steps to Reproduce")
                for step in finding["poc"]["steps_to_reproduce"]:
                    md.append(f"{step}")
                md.append("")

            if finding.get("poc") and \
               finding["poc"].get("curl_command"):
                md.append("### Proof of Concept")
                md.append("```bash")
                md.append(finding["poc"]["curl_command"])
                md.append("```")
                md.append("")

            md.append("### Impact")
            md.append(finding.get("business_impact", "See details above"))
            md.append("")

            md.append("### Remediation")
            md.append(finding.get("remediation", "See OWASP guidelines"))
            md.append("")

            refs = finding.get("references", {})
            md.append("### References")
            md.append(f"- OWASP: {refs.get('owasp', 'N/A')}")
            for cwe in refs.get("cwe", [])[:2]:
                md.append(f"- {cwe}")
            md.append("")
            md.append("---")
            md.append("")

        return "\n".join(md)


if __name__ == "__main__":
    # Test the report generator
    reporter = BountyReport(
        "https://sharpener.tech",
        researcher_name="Ajeet Kumar"
    )

    # Test CVSS calculation
    print("\n--- CVSS Score Tests ---")
    test_vulns = [
        "SQL Injection",
        "XSS Reflected",
        "IDOR",
        "SSRF",
        "Open Redirect",
        "Missing Security Header"
    ]

    for vuln in test_vulns:
        cvss = reporter.get_cvss_preset(vuln)
        payout = reporter.estimate_payout(cvss["score"])
        print(f"{vuln}:")
        print(f"  CVSS: {cvss['score']} ({cvss['severity']})")
        print(f"  Payout: {payout['tier']}")

    # Generate test report
    print("\n--- Generating Test Report ---")

    test_findings = [
        {
            "type": "IDOR",
            "severity": "HIGH",
            "url": "https://sharpener.tech/api/user/1547",
            "detail": "User data accessible by changing ID parameter",
            "evidence": "Status 200 returned with another user's data",
            "analysis": {
                "plain_english": "Anyone can access other users private data",
                "attack_scenario": "Change user ID in URL to access any account",
                "business_impact": "All 50,000 users data exposed",
                "immediate_fix": "Add authorization checks on all user endpoints"
            }
        },
        {
            "type": "Missing Security Header",
            "severity": "MEDIUM",
            "url": "https://sharpener.tech",
            "detail": "X-Frame-Options header missing — clickjacking possible",
            "evidence": "No X-Frame-Options in response headers",
            "analysis": {
                "plain_english": "Website can be embedded in malicious pages",
                "attack_scenario": "Attacker creates fake page embedding target",
                "business_impact": "Users tricked into performing unintended actions",
                "immediate_fix": "Add X-Frame-Options: DENY to all responses"
            }
        }
    ]

    files = reporter.export_report(test_findings)

    print(f"\n✅ Reports generated successfully!")
    print(f"Files created:")
    for f in files:
        print(f"  → {f}")

    print(f"\n--- REPORT SUMMARY ---")
    print(f"Target: {reporter.target}")
    print(f"Researcher: {reporter.researcher}")
    print(f"Total Findings: {len(reporter.findings)}")
    
    critical = sum(1 for f in reporter.findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in reporter.findings if f["severity"] == "HIGH")
    medium = sum(1 for f in reporter.findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in reporter.findings if f["severity"] == "LOW")
    
    print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
    
    print(f"\n--- PAYOUT TIERS ---")
    for f in reporter.findings:
        print(f"  [{f['id']}] {f['title']}")
        print(f"       CVSS: {f['cvss']['score']} | Tier: {f['payout_estimate']['tier']}")    