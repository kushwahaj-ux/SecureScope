import nmap
import socket
import json
import requests
from datetime import datetime
import verifier

class NetworkScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        print("[+] SecureScope Core Engine Initialized Successfully!")

    def resolve_target(self, target):
        """
        Extracts clean domain name and resolves it to an IP address.
        """
        try:
            clean_target = target
            if clean_target.startswith("http://"):
                clean_target = clean_target.replace("http://", "")
            elif clean_target.startswith("https://"):
                clean_target = clean_target.replace("https://", "")
            
            clean_target = clean_target.split("/")[0].split(":")[0]
            ip = socket.gethostbyname(clean_target)
            return clean_target, ip
        except socket.gaierror:
            return target, target

    def scan_target(self, target, port_range="1-1000"):
        """
        Performs an infrastructure-level network port scan using Nmap.
        """
        domain, ip = self.resolve_target(target)
        print(f"\n[*] Launching Network Scan for: {domain} ({ip})")
        
        try:
            self.scanner.scan(ip, port_range, arguments="-sV")
            results = {
                "target": domain,
                "ip": ip,
                "scan_time": datetime.now().isoformat(),
                "ports": []
            }
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    for port in sorted(self.scanner[host][proto].keys()):
                        svc = self.scanner[host][proto][port]
                        if svc["state"] == "open":
                            results["ports"].append({
                                "port": port,
                                "service": svc["name"],
                                "version": svc.get("version", "")
                            })  
            return results
        except Exception as e:
            print(f"[-] Network scan failed: {e}")
            return {"target": domain, "ip": ip, "error": str(e), "ports": []}

    def scan_web_assets(self, target_url):
        """
        Performs an application-level web scan for sensitive files.
        Uses the verifier module to analyze and filter out False 404 responses.
        """
        # Ensure the URL has a proper http/https scheme prefix
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        print(f"\n[*] Launching Web Security Audit for: {target_url}")
        
        # 1. Establish the false-positive protection baseline fingerprint
        baseline = verifier.establish_baseline(target_url)
        if baseline:
            print(f"[+] Advanced Anti-False-Positive Engine Enabled.")
            print(f"    |- Baseline Status Captured: {baseline['status_code']}")
            print(f"    |- Baseline Page Size: {baseline['content_length']} bytes")
        else:
            print("[-] Warning: Failed to establish baseline fingerprint. Scanning in fallback mode.")

        # 2. Key high-risk exposures to hunt for
        sensitive_files = [".env", ".git/config", "db_backup.sql", "web.config"]
        findings = []

        # 3. Scanning loop with fingerprint filtering
        for file in sensitive_files:
            url = f"{target_url.rstrip('/')}/{file}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    # Pass the page response to our module to see if it's a fake match
                    if verifier.is_false_positive(response, baseline):
                        print(f"  |-[➖] Filtered False Positive: /{file} (Matches wildcard error structure)")
                    else:
                        print(f"  |-[🚨] TRUE CRITICAL EXPOSURE FOUND: {url}")
                        findings.append({
                            "file": file,
                            "url": url,
                            "status": "Exposed",
                            "content_length": len(response.content)
                        })
            except requests.RequestException:
                pass
                
        return findings

if __name__ == "__main__":
    print("==================================================")
    print("🛡️  SecureScope Enterprise Scanner Engine v2.0")
    print("==================================================")
    
    scanner = NetworkScanner()
    
    # 🎯 Set your target here
    target_host = "scanme.nmap.org"
    
    # 1. Run Port Scan
    port_results = scanner.scan_target(target_host, port_range="1-1000")
    print("\n[+] Infrastructure Audit Results Summary:")
    print(json.dumps(port_results, indent=2))
    
    # 2. Run Advanced Web Scan
    web_results = scanner.scan_web_assets(target_host)
    print("\n[+] Web Asset Audit Results Summary:")
    print(json.dumps(web_results, indent=2))
    
    print("\n==================================================")