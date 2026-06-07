from cors_scanner import CORSScanner
from dotenv import load_dotenv
from subdomain_scanner import SubdomainScanner
load_dotenv()
from flask import Flask, request, jsonify, send_file
from scanner import NetworkScanner
from web_scanner import WebVulnerabilityScanner
from cve_lookup import CVELookup
from ai_analyzer import AIAnalyzer
from report import ReportGenerator
from frontend_analyzer import FrontendAnalyzer
from graphql_scanner import GraphQLScanner
from cors_scanner import CORSScanner
from jwt_analyzer import JWTAnalyzer
from ssl_scanner import SSLScanner
from advanced_scanner import AdvancedScanner
from vulnerability_kb import generate_security_report
from authenticated_scanner import AuthenticatedScanner
from ai_security_scanner import AISecurityScanner
from cloud_scanner import CloudScanner
from supply_chain_scanner import SupplyChainScanner
from bounty_report import BountyReport
from poc_generator import PoCGenerator
from host_header_tester import HostHeaderTester
from websocket_scanner import WebSocketScanner
from compliance import ComplianceReporter
import mysql.connector
import json
import threading
import uuid
from datetime import datetime
import os
import html

app = Flask(__name__)

# Initialize all modules
net_scanner = NetworkScanner()
cve_lookup = CVELookup()
ai = AIAnalyzer()

# MariaDB connection settings
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": os.getenv("MARIADB_PASSWORD", "0000nn"),
    "database": "securescope",
    "auth_plugin": "mysql_native_password"
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id VARCHAR(20) PRIMARY KEY,
            target TEXT,
            scan_time TEXT,
            status TEXT,
            results LONGTEXT
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("✅ MariaDB connected successfully!")

def calculate_risk_score(findings, ports=None):
    score = 0
    for f in findings:
        if f.get("severity") == "CRITICAL":
            score += 10
        elif f.get("severity") == "HIGH":
            score += 7
        elif f.get("severity") == "MEDIUM":
            score += 4
        elif f.get("severity") == "LOW":
            score += 1

    # Add CVE scores from ports
    if ports:
        for port in ports:
            cve_count = len(port.get("cves", []))
            score += cve_count * 5

    return score

@app.route("/")
def home():
    return """
    <html>
    <head><title>SecureScope</title></head>
    <body style="background:#0a0e1a; color:#fff; font-family:Arial; text-align:center; padding:50px">
        <h1 style="color:#5dcaa5">🔐 SecureScope</h1>
        <h3>AI-Powered Vulnerability Scanner — Enterprise Edition</h3>
        <p style="color:#64748b">14 Security Categories | False Positive Reduction | AI Analysis</p>

        <form method="POST" action="/scan">
            <input name="target" placeholder="Enter target URL or IP"
                   style="padding:12px; width:350px; border-radius:5px;
                          border:1px solid #1e3a5f; background:#0d1b2a;
                          color:#fff; font-size:14px; margin-bottom:15px">
            <br>

            <div style="margin:15px 0; text-align:left;
                        display:inline-block; background:#0d1b2a;
                        padding:20px; border-radius:8px;
                        border:1px solid #1e3a5f">
                <p style="color:#5dcaa5; margin-bottom:10px; font-weight:bold">
                    Select Scan Modules:
                </p>

                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="network" checked>
                    &nbsp;🌐 Network + Port Scanner
                </label>

                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="web" checked>
                    &nbsp;🕷️ Web Vulnerability Scanner (OWASP Top 10)
                </label>

                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="frontend" checked>
                    &nbsp;🔍 Frontend + JavaScript Analyzer (11 Categories)
                </label>

                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="graphql">
                    &nbsp;⚡ GraphQL Security Scanner
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="cors">
                    &nbsp;🔒 CORS Misconfiguration Scanner
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                    <input type="checkbox" name="modules" value="subdomain">
                    &nbsp;🔎 Subdomain Enumeration
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="jwt">
                &nbsp;🔑 JWT Token Analyzer
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="ssl">
                &nbsp;🔐 SSL/TLS Deep Scanner
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="advanced">
                &nbsp;⚡ Advanced Scanner (SSRF, IDOR, DNS, Rate Limit)
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="ai_security">
                &nbsp;🤖 AI Security Scanner (OWASP LLM Top 10)
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="cloud">
                &nbsp;☁️ Cloud Security Scanner (AWS/Azure/GCP)
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="supply_chain">
                &nbsp;🔗 Supply Chain Scanner (Libraries/Dependencies)
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="host_header">
                &nbsp;🎯 Host Header Injection Tester
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="websocket">
                &nbsp;🔌 WebSocket Security Scanner
                </label>
                <label style="display:block; margin:8px 0; cursor:pointer">
                <input type="checkbox" name="modules" value="compliance">
                &nbsp;📋 Compliance Reporter (PCI-DSS, ISO 27001, GDPR, CERT-In)
                </label>
            </div>
            <div style="margin:15px 0; text-align:left;
                        display:inline-block; background:#0d1b2a;
                        padding:20px; border-radius:8px;
                        border:1px solid #0f6e56">
                <p style="color:#5dcaa5; font-weight:bold">
                    🔐 Optional: Authenticated Scanning
                </p>
                <input name="login_url" placeholder="Login URL (e.g. /api/auth/login)"
                       style="padding:8px; width:300px; background:#0a0e1a;
                              color:#fff; border:1px solid #1e3a5f; border-radius:4px;
                              margin:4px 0; display:block">
                <input name="auth_username" placeholder="Username/Email"
                       style="padding:8px; width:300px; background:#0a0e1a;
                              color:#fff; border:1px solid #1e3a5f; border-radius:4px;
                              margin:4px 0; display:block">
                <input name="auth_password" type="password" placeholder="Password"
                       style="padding:8px; width:300px; background:#0a0e1a;
                              color:#fff; border:1px solid #1e3a5f; border-radius:4px;
                              margin:4px 0; display:block">
                <input name="jwt_token" placeholder="OR paste JWT token here"
                       style="padding:8px; width:300px; background:#0a0e1a;
                              color:#fff; border:1px solid #1e3a5f; border-radius:4px;
                              margin:4px 0; display:block">
                <input name="session_cookie" placeholder="OR paste session cookie here"
                       style="padding:8px; width:300px; background:#0a0e1a;
                              color:#fff; border:1px solid #1e3a5f; border-radius:4px;
                              margin:4px 0; display:block">
            </div>
            <br>
            <button type="submit"
                    style="padding:12px 30px; background:#5dcaa5;
                           border:none; border-radius:5px; cursor:pointer;
                           font-size:16px; font-weight:bold; color:#0a0e1a;
                           margin-top:15px">
                🚀 Start Scan
            </button>
        </form>
    </body>
    </html>
    """

@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    scan_id = str(uuid.uuid4())[:8]
    selected_modules = request.form.getlist("modules")
    login_url = request.form.get("login_url", "").strip()
    auth_username = request.form.get("auth_username", "").strip()
    auth_password = request.form.get("auth_password", "").strip()
    jwt_token = request.form.get("jwt_token", "").strip()
    session_cookie = request.form.get("session_cookie", "").strip()

    # Save scan as started
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans VALUES (%s,%s,%s,%s,%s)",
        (scan_id, target, datetime.now().isoformat(), "running", "{}")
    )
    conn.commit()
    cursor.close()
    conn.close()

    def run_scan():
        all_findings = []
        modules = selected_modules

        # Web scan
        if "web" in modules:
            ws = WebVulnerabilityScanner(target)
            ws.check_security_headers()
            ws.check_admin_panels()
            ws.check_sensitive_files()
            ws.crawl_forms()
            for f in ws.findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # Network scan
        net_results = {"ports": []}
        if "network" in modules:
            net_results = net_scanner.scan_target(target)
            for port in net_results.get("ports", []):
                cves = cve_lookup.search(port["service"], port["version"])
                port["cves"] = cves

        # Frontend scan
        if "frontend" in modules:
            fa = FrontendAnalyzer(target)
            frontend_findings = fa.run_full_analysis()
            for f in frontend_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # GraphQL scan
        if "graphql" in modules:
            gql = GraphQLScanner(target)
            graphql_findings = gql.run_full_scan()
            for f in graphql_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # CORS scan
        if "cors" in modules:
            cors = CORSScanner(target)
            cors_findings = cors.run_full_scan()
            for f in cors_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)  

        # JWT scan
        if "jwt" in modules:
            jwt = JWTAnalyzer(target)
            jwt_findings = jwt.run_full_scan()
            for f in jwt_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # JWT scan
        # SSL scan
        if "ssl" in modules:
            ssl_scan = SSLScanner(target)
            ssl_findings = ssl_scan.run_full_scan()
            for f in ssl_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)      
        # Advanced scan
        if "advanced" in modules:
            adv = AdvancedScanner(target)
            adv_findings = adv.run_full_scan()
            for f in adv_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)   
        # AI Security scan
        if "ai_security" in modules:
            ai_sec = AISecurityScanner(target)
            ai_findings = ai_sec.run_full_scan()
            for f in ai_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # Cloud scan
        if "cloud" in modules:
            cloud = CloudScanner(target)
            cloud_findings = cloud.run_full_scan()
            for f in cloud_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # Supply chain scan
        if "supply_chain" in modules:
            sc = SupplyChainScanner(target)
            sc_findings = sc.run_full_scan()
            for f in sc_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)  

        # Host header scan
        if "host_header" in modules:
            hht = HostHeaderTester(target)
            hht_findings = hht.run_full_scan()
            for f in hht_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)

        # Compliance report
        if "compliance" in modules:
            comp = ComplianceReporter(target, target)
            comp.generate_report(all_findings)        

        # WebSocket scan
        if "websocket" in modules:
            ws = WebSocketScanner(target)
            ws_findings = ws.run_full_scan()
            for f in ws_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)                     

        # Authenticated scan
        if any([login_url, jwt_token, session_cookie]):
            print("[*] Running authenticated scan...")
            auth_scanner = AuthenticatedScanner(target)
            auth_findings = auth_scanner.run_full_scan(
                login_url=login_url or None,
                username=auth_username or None,
                password=auth_password or None,
                jwt_token=jwt_token or None,
                cookie=session_cookie or None
            )
            for f in auth_findings:
                analysis = ai.analyze(f["type"], f["detail"], f["severity"])
                f["analysis"] = analysis
                all_findings.append(f)                      

        # Calculate risk score and summary
        # Add port CVE findings to summary
        port_findings = []
        for port in net_results.get("ports", []):
            cves = port.get("cves", [])
            if cves:
                # Group ALL CVEs per port into ONE finding
                cve_list = ", ".join([
                    str(c.get("id", c)) if isinstance(c, dict)
                    else str(c)
                    for c in cves[:5]
                ])
                port_findings.append({
                    "type": f"CVE in Port {port['port']} ({port.get('service', '')})",
                    "severity": "HIGH",
                    "detail": f"Port {port['port']} running {port.get('service', 'unknown')} {port.get('version', '')} has {len(cves)} known CVEs: {cve_list}",
                    "evidence": f"Service: {port.get('service', '')} | Version: {port.get('version', '')} | CVEs: {len(cves)}",
                    "url": f"http://{net_results.get('host', '')}"
                })

        # Calculate risk score and summary
        risk_score = calculate_risk_score(
            all_findings,
            net_results.get("ports", [])
        )
        
            
            
        
        # Generate KB security report
        # Verification Engine — filter false positives + detect chains
        from verification_engine import VerificationEngine
        ve = VerificationEngine(target)
        verified_results = ve.verify_all_findings(all_findings)
        all_findings = verified_results["verified_findings"]
        chains = verified_results["chains"]
        summary = ai.executive_summary(
            target,
            all_findings + port_findings
        )
        # Generate PoC and bug bounty report
        poc_gen = PoCGenerator(target)
        all_findings = poc_gen.generate_pocs_for_findings(all_findings)

        reporter = BountyReport(target, "Ajeet Kumar")
        report_files = reporter.export_report(all_findings)
        from vulnerability_kb import generate_security_report
        kb_report = generate_security_report(
            all_findings,
            net_results.get("ports", [])
        )
        security_score = kb_report["security_score"]
        risk_level_kb = kb_report["risk_level"]
        recommendations = kb_report["recommendations"]

        results = {
            "scan_id": scan_id,
            "target": target,
            "web_findings": all_findings,
            "ports": net_results.get("ports", []),
            "summary": summary,
            "total": len(all_findings),  # now counted AFTER verification
            "risk_score": risk_score,
            "modules_run": modules,
            "security_score": security_score,
            "risk_level_kb": risk_level_kb,
            "recommendations": recommendations,
            "bounty_reports": report_files,
            "chains": chains,
            "verification_stats": verified_results["stats"],
            "port_findings_count": len(port_findings)
        }

        # Save results to MariaDB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scans SET status=%s, results=%s WHERE id=%s",
            ("complete", json.dumps(results), scan_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[✅] Scan {scan_id} complete — {len(all_findings)} findings | Risk Score: {risk_score}")

    threading.Thread(target=run_scan).start()

    modules_text = ", ".join(selected_modules) if selected_modules else "none"
    return f"""
    <html>
    <head><title>Scanning...</title>
    <meta http-equiv="refresh" content="5;url=/results/{scan_id}">
    </head>
    <body style="background:#0a0e1a; color:#fff; font-family:Arial; text-align:center; padding:50px">
        <h1 style="color:#5dcaa5">🔍 Scanning {target}...</h1>
        <p>Scan ID: {scan_id}</p>
        <p style="color:#64748b">Modules: {modules_text}</p>
        <p>Please wait — redirecting to results in 5 seconds...</p>
    </body>
    </html>
    """

@app.route("/results/<scan_id>")
def get_results(scan_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT status, results FROM scans WHERE id=%s",
        (scan_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return "<h1>Scan not found</h1>"

    status, results_json = row

    if status == "running":
        return f"""
        <html>
        <head><meta http-equiv="refresh" content="3;url=/results/{scan_id}"></head>
        <body style="background:#0a0e1a; color:#fff; font-family:Arial; text-align:center; padding:50px">
            <h1 style="color:#5dcaa5">⏳ Scan in progress...</h1>
            <p>Refreshing automatically...</p>
        </body>
        </html>
        """

    results = json.loads(results_json)

    security_score = results.get("security_score", 100)
    if security_score >= 80:
        risk_color = "#44ff44"
        risk_label = "LOW RISK"
    elif security_score >= 60:
        risk_color = "#ffcc00"
        risk_label = "MEDIUM RISK"
    elif security_score >= 40:
        risk_color = "#ff8800"
        risk_label = "HIGH RISK"
    else:
        risk_color = "#ff4444"
        risk_label = "CRITICAL RISK"

    findings_html = ""
    for f in results.get("web_findings", []):
        color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                 "MEDIUM": "#ffcc00", "LOW": "#44ff44"}.get(f["severity"], "#fff")
        analysis = f.get("analysis", {})
        safe_type = html.escape(str(f.get("type", "")))
        safe_detail = html.escape(str(f.get("detail", "")))
        safe_english = html.escape(str(analysis.get("plain_english", "")))
        safe_scenario = html.escape(str(analysis.get("attack_scenario", "")))
        safe_fix = html.escape(str(analysis.get("immediate_fix", "")))

        findings_html += f"""
        <div style="background:#0d1b2a; border:1px solid #1e3a5f;
                    border-radius:8px; padding:16px; margin:10px 0; text-align:left">
            <span style="color:{color}; font-weight:bold">[{f["severity"]}]</span>
            <strong style="color:#fff"> {safe_type}</strong>
            <p style="color:#94a3b8">{safe_detail}</p>
            <p style="color:#5dcaa5">📋 {safe_english}</p>
            <p style="color:#ff8800">⚔️ {safe_scenario}</p>
            <p style="color:#44ff44">🔧 {safe_fix}</p>
        </div>
        """

    ports_html = ""
    for p in results.get("ports", []):
        ports_html += f"""
        <div style="background:#0d1b2a; border:1px solid #1e3a5f;
                    border-radius:8px; padding:10px; margin:5px 0; text-align:left">
            <span style="color:#5dcaa5">Port {p["port"]}</span> —
            {p["service"]} {p["version"]}
            — CVEs found: {len(p.get("cves", []))}
        </div>
        """

    modules_run = results.get("modules_run", [])
    modules_html = " | ".join([f"✅ {m}" for m in modules_run])

    return f"""
    <html>
    <head><title>SecureScope Results</title></head>
    <body style="background:#0a0e1a; color:#fff; font-family:Arial;
                 padding:30px; max-width:900px; margin:0 auto">
        <h1 style="color:#5dcaa5">🔐 SecureScope Results</h1>
        <h3>Target: {results["target"]}</h3>
        <p style="color:#64748b; font-size:13px">Modules run: {modules_html}</p>
        <p style="color:#5dcaa5">Total Findings: {results["total"]}</p>
        <p style="color:{risk_color}; font-size:22px; font-weight:bold">
            Security Score: {results.get("security_score", 0)}/100
            — {risk_label}
        </p>
        <div style="background:#0d1b2a; border:1px solid #1e3a5f; 
                    border-radius:8px; padding:16px; margin:10px 0">
            <p style="color:#5dcaa5; font-weight:bold">
                📋 Recommendations:
            </p>
            {"".join([f'<p style="color:#94a3b8">• {r}</p>' 
                      for r in results.get("recommendations", [])])}
        </div>

        <h2 style="color:#5dcaa5; border-bottom:1px solid #1e3a5f; padding-bottom:8px">
            Executive Summary
        </h2>
        <p style="color:#94a3b8; line-height:1.8">{results.get("summary", "")}</p>

        <h2 style="color:#5dcaa5; border-bottom:1px solid #1e3a5f; padding-bottom:8px">
            Vulnerability Findings
        </h2>
        {findings_html if findings_html else '<p style="color:#64748b">No vulnerabilities found</p>'}

        <h2 style="color:#5dcaa5; border-bottom:1px solid #1e3a5f; padding-bottom:8px">
            Open Ports
        </h2>
        {ports_html if ports_html else '<p style="color:#64748b">No open ports found</p>'}

        <br>
        <a href="/" style="color:#5dcaa5">← New Scan</a>
        &nbsp;&nbsp;
        <a href="/report/{scan_id}"
           style="color:#ff8800; font-weight:bold;
                  padding:10px 20px; background:#0d1b2a;
                  border:1px solid #ff8800; border-radius:5px;
                  text-decoration:none">
            📄 Download PDF Report
        </a>
    </body>
    </html>
    """

@app.route("/report/<scan_id>")
def download_report(scan_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT results FROM scans WHERE id=%s", (scan_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        results = json.loads(row[0])
        gen = ReportGenerator()
        path = gen.generate(results, f"report_{scan_id}.pdf")
        return send_file(path, as_attachment=True)
    return "Scan not found", 404

if __name__ == "__main__":
    init_db()
    print("🔐 SecureScope Dashboard starting...")
    print("📊 Open http://localhost:5000 in browser")
    app.run(debug=True, host="0.0.0.0", port=5000)