from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch
from datetime import datetime
import json

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.colors = {
            "primary": HexColor("#0F6E56"),
            "dark": HexColor("#0A0E1A"),
            "critical": HexColor("#FF4444"),
            "high": HexColor("#FF8800"),
            "medium": HexColor("#FFCC00"),
            "low": HexColor("#44FF44"),
            "gray": HexColor("#64748B"),
            "light": HexColor("#E1F5EE")
        }
        print("Report Generator Ready!")

    def clean_text(self, text):
        if not text:
            return ""
        text = str(text)
        text = text.replace("&", "and")
        text = text.replace("<", "")
        text = text.replace(">", "")
        text = text.replace("\x00", "")
        return text    
        

    def generate(self, results, filename="securescope_report.pdf"):
        import os
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/{filename}"
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        story = []

        # Cover Page
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph(
            "SECURESCOPE",
            ParagraphStyle("title",
                fontSize=28, textColor=self.colors["primary"],
                alignment=1, fontName="Helvetica-Bold")
        ))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "AI-Powered Vulnerability Assessment Report",
            ParagraphStyle("subtitle",
                fontSize=16, textColor=self.colors["gray"],
                alignment=1, fontName="Helvetica")
        ))
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%", thickness=2,
                                color=self.colors["primary"]))
        story.append(Spacer(1, 0.3*inch))

        # Scan Info
        story.append(Paragraph(
            f"Target: {results.get('target', 'N/A')}",
            ParagraphStyle("info",
                fontSize=12, textColor=self.colors["dark"],
                fontName="Helvetica-Bold")
        ))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(
            f"Scan Date: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            ParagraphStyle("info2",
                fontSize=11, textColor=self.colors["gray"],
                fontName="Helvetica")
        ))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(
            f"Total Findings: {results.get('total', 0)}",
            ParagraphStyle("info3",
                fontSize=11, textColor=self.colors["gray"],
                fontName="Helvetica")
        ))
        story.append(Spacer(1, 0.5*inch))

        # Executive Summary
        story.append(Paragraph(
            "EXECUTIVE SUMMARY",
            ParagraphStyle("section",
                fontSize=14, textColor=self.colors["primary"],
                fontName="Helvetica-Bold")
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=self.colors["primary"]))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            self.clean_text(results.get("summary", "No summary available")),
            ParagraphStyle("body",
                fontSize=10, textColor=self.colors["dark"],
                fontName="Helvetica", leading=16)
        ))
        story.append(Spacer(1, 0.5*inch))

        # Web Findings
        story.append(Paragraph(
            "WEB VULNERABILITY FINDINGS",
            ParagraphStyle("section2",
                fontSize=14, textColor=self.colors["primary"],
                fontName="Helvetica-Bold")
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=self.colors["primary"]))
        story.append(Spacer(1, 0.2*inch))

        findings = results.get("web_findings", [])
        if findings:
            for f in findings:
                severity = f.get("severity", "LOW")
                color_map = {
                    "CRITICAL": self.colors["critical"],
                    "HIGH": self.colors["high"],
                    "MEDIUM": self.colors["medium"],
                    "LOW": self.colors["low"]
                }
                sev_color = color_map.get(severity, self.colors["gray"])
                story.append(Paragraph(
                    f"[{severity}] {f.get('type', '')}",
                    ParagraphStyle("finding_header",
                        fontSize=12, textColor=sev_color,
                        fontName="Helvetica-Bold")
                ))
                story.append(Paragraph(
                    f"Detail: {f.get('detail', '')}",
                    ParagraphStyle("finding_detail",
                        fontSize=10, textColor=self.colors["dark"],
                        fontName="Helvetica", leading=14)
                ))
                analysis = f.get("analysis", {})
                if analysis:
                    story.append(Paragraph(
                        f"Plain English: {self.clean_text(analysis.get('plain_english', ''))}",
                        ParagraphStyle("plain",
                            fontSize=10, textColor=self.colors["primary"],
                            fontName="Helvetica-Oblique", leading=14)
                    ))
                    story.append(Paragraph(
                        f"Attack Scenario: {self.clean_text(analysis.get('attack_scenario', ''))}",
                        ParagraphStyle("attack",
                            fontSize=10, textColor=self.colors["high"],
                            fontName="Helvetica", leading=14)
                    ))
                    story.append(Paragraph(
                        f"Immediate Fix: {self.clean_text(analysis.get('immediate_fix', ''))}",
                        ParagraphStyle("fix",
                            fontSize=10, textColor=self.colors["dark"],
                            fontName="Helvetica", leading=14)
                    ))
                    story.append(Paragraph(
                        f"Business Impact: {self.clean_text(analysis.get('business_impact', ''))}",
                        ParagraphStyle("impact",
                            fontSize=10, textColor=self.colors["gray"],
                            fontName="Helvetica", leading=14)
                    ))
                story.append(Spacer(1, 0.2*inch))
                story.append(HRFlowable(width="100%", thickness=0.5,
                                        color=self.colors["gray"]))
                story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph(
                "No web vulnerabilities found.",
                ParagraphStyle("none",
                    fontSize=10, textColor=self.colors["gray"],
                    fontName="Helvetica")
            ))

        story.append(Spacer(1, 0.3*inch))

        # Open Ports Table
        story.append(Paragraph(
            "OPEN PORTS & SERVICES",
            ParagraphStyle("section3",
                fontSize=14, textColor=self.colors["primary"],
                fontName="Helvetica-Bold")
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=self.colors["primary"]))
        story.append(Spacer(1, 0.2*inch))

        ports = results.get("ports", [])
        if ports:
            table_data = [["Port", "Service", "Version", "CVEs Found"]]
            for p in ports:
                table_data.append([
                    str(p.get("port", "")),
                    p.get("service", ""),
                    p.get("version", "")[:30],
                    str(len(p.get("cves", [])))
                ])
            table = Table(table_data,
                         colWidths=[1*inch, 1.5*inch, 3*inch, 1.2*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), self.colors["primary"]),
                ("TEXTCOLOR", (0,0), (-1,0), white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1),
                 [self.colors["light"], white]),
                ("GRID", (0,0), (-1,-1), 0.5, self.colors["gray"]),
                ("ALIGN", (0,0), (-1,-1), "CENTER"),
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                ("PADDING", (0,0), (-1,-1), 6),
            ]))
            story.append(table)
        else:
            story.append(Paragraph(
                "No open ports found.",
                ParagraphStyle("none2",
                    fontSize=10, textColor=self.colors["gray"],
                    fontName="Helvetica")
            ))

        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=self.colors["primary"]))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(
            "Generated by SecureScope — AI-Powered Vulnerability Scanner | Confidential",
            ParagraphStyle("footer",
                fontSize=8, textColor=self.colors["gray"],
                alignment=1, fontName="Helvetica-Oblique")
        ))

        doc.build(story)
        print(f"✅ Report generated: {filename}")
        return filename


if __name__ == "__main__":
    report = ReportGenerator()
    test_results = {
        "target": "https://emedsmart.co",
        "total": 2,
        "summary": "Security assessment completed. Two medium severity findings identified.",
        "web_findings": [
            {
                "type": "Missing Security Header",
                "detail": "Content-Security-Policy missing",
                "severity": "MEDIUM",
                "analysis": {
                    "plain_english": "Website is missing important security header",
                    "attack_scenario": "Attacker can inject malicious scripts",
                    "immediate_fix": "Add Content-Security-Policy header",
                    "business_impact": "User data could be stolen"
                }
            }
        ],
        "ports": [
            {"port": 80, "service": "http", "version": "2.4.7", "cves": []},
            {"port": 22, "service": "ssh", "version": "8.0", "cves": [{"id": "CVE-2023-1234"}]}
        ]
    }
    report.generate(test_results, "test_report.pdf")