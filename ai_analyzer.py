from google import genai
from google.genai import types
import os
import json

class AIAnalyzer:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("⚠️ WARNING: GEMINI_API_KEY not set!")
        
        self.client = genai.Client(api_key=api_key)
        self.model_name = "gemini-2.5-flash"
        print("AI Analyzer Ready!")

    def analyze(self, finding_type, details, severity):
        if not finding_type or not details:
            return {
                "plain_english": "No finding provided",
                "risk_level": "UNKNOWN",
                "attack_scenario": "N/A",
                "immediate_fix": "N/A",
                "business_impact": "N/A"
            }
            
        prompt = f"""
You are a senior penetration tester writing a security report.
Analyze this finding and respond ONLY in valid JSON format.

Finding Type: {finding_type}
Details: {details}
Severity: {severity}

Respond with exactly this JSON structure:
{{
    "plain_english": "explain in 1-2 sentences a non-technical manager understands",
    "risk_level": "{severity}",
    "attack_scenario": "how exactly would a hacker exploit this step by step",
    "immediate_fix": "exact technical steps to fix this vulnerability",
    "business_impact": "what happens to the business if exploited"
}}
"""
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            text = response.text.strip()
            return json.loads(text)
            
        except json.JSONDecodeError:
            return {
                "plain_english": details,
                "risk_level": severity,
                "attack_scenario": "Manual analysis required",
                "immediate_fix": "Review and patch the vulnerability",
                "business_impact": "Potential unauthorized access"
            }
        except Exception as e:
            print(f"AI error: {e}")
            return {
                "plain_english": details,
                "risk_level": severity,
                "attack_scenario": "Manual analysis required",
                "immediate_fix": "Review and patch the vulnerability",
                "business_impact": "Potential unauthorized access"
            }

    def executive_summary(self, target, findings):
        if not findings:
            return f"No vulnerabilities found on {target}. System appears secure."
            
        counts = {
            "CRITICAL": sum(1 for f in findings if f.get("risk_level") == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.get("risk_level") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("risk_level") == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.get("risk_level") == "LOW"),
        }
        
        prompt = f"""
You are a senior cybersecurity consultant writing an executive summary.
Write exactly 3 paragraphs for a CEO — clear, business focused, zero technical jargon.

Target: {target}
Total Findings: {len(findings)}
Critical: {counts['CRITICAL']}
High: {counts['HIGH']}
Medium: {counts['MEDIUM']}
Low: {counts['LOW']}

Paragraph 1: Overall security posture
Paragraph 2: Most urgent risks and business impact
Paragraph 3: Recommended immediate actions
"""
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            print(f"Summary error: {e}")
            return f"Security assessment of {target} completed. {len(findings)} findings identified."

if __name__ == "__main__":
    ai = AIAnalyzer()
    print("\n--- Running Empty Input Safety Check ---")
    empty = ai.analyze("", "", "")
    print(json.dumps(empty, indent=2))