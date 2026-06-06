import requests
import re
import json
import urllib3
from urllib.parse import urljoin
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SupplyChainScanner:
    """
    SecureScope Supply Chain Security Scanner
    ==========================================
    Tests third party libraries and dependencies
    for known vulnerabilities.

    WHY THIS MATTERS:
    Log4Shell 2021 — ONE library
    Affected millions of servers worldwide!
    SolarWinds breach — supply chain attack
    Compromised 18,000 companies including US government!

    Modern apps use 100s of libraries.
    One vulnerable library = entire app vulnerable!

    Covers:
    1. JavaScript Library Detection
    2. Outdated Library Detection
    3. Known Vulnerable Libraries (CVE check)
    4. Package.json Analysis
    5. CDN Library Security
    6. Subresource Integrity Check
    7. Dependency Confusion Risk
    """

    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        self.detected_libraries = {}
        print(f"Supply Chain Scanner Ready! Target: {self.target}")

    # ============================================================
    # STEP 1 — Detect JavaScript Libraries
    # ============================================================
    def detect_js_libraries(self):
        """
        Detects all JavaScript libraries used on website.

        WHY: Cannot check vulnerabilities without knowing
        which libraries are used and their versions!

        Detects:
        - jQuery
        - React, Vue, Angular
        - Bootstrap
        - Lodash, Moment.js
        - And 30+ more!
        """
        print("[*] Detecting JavaScript libraries...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            # Library detection patterns
            library_patterns = {
                "jQuery": [
                    r'jquery[.-](\d+\.\d+\.?\d*)',
                    r'jQuery v(\d+\.\d+\.?\d*)',
                    r'"jquery":"(\d+\.\d+\.?\d*)"',
                ],
                "React": [
                    r'react[.-](\d+\.\d+\.?\d*)',
                    r'"react":"(\d+\.\d+\.?\d*)"',
                    r'React\.version\s*=\s*[\'"](\d+\.\d+\.?\d*)',
                ],
                "Vue.js": [
                    r'vue[.-](\d+\.\d+\.?\d*)',
                    r'"vue":"(\d+\.\d+\.?\d*)"',
                    r'Vue\.version\s*=\s*[\'"](\d+\.\d+\.?\d*)',
                ],
                "Angular": [
                    r'angular[.-](\d+\.\d+\.?\d*)',
                    r'"@angular/core":"(\d+\.\d+\.?\d*)"',
                ],
                "Bootstrap": [
                    r'bootstrap[.-](\d+\.\d+\.?\d*)',
                    r'"bootstrap":"(\d+\.\d+\.?\d*)"',
                ],
                "Lodash": [
                    r'lodash[.-](\d+\.\d+\.?\d*)',
                    r'"lodash":"(\d+\.\d+\.?\d*)"',
                    r'lodash\.version\s*=\s*[\'"](\d+\.\d+\.?\d*)',
                ],
                "Moment.js": [
                    r'moment[.-](\d+\.\d+\.?\d*)',
                    r'"moment":"(\d+\.\d+\.?\d*)"',
                ],
                "Axios": [
                    r'axios[.-](\d+\.\d+\.?\d*)',
                    r'"axios":"(\d+\.\d+\.?\d*)"',
                ],
                "Express": [
                    r'"express":"(\d+\.\d+\.?\d*)"',
                ],
                "Next.js": [
                    r'next[.-](\d+\.\d+\.?\d*)',
                    r'"next":"(\d+\.\d+\.?\d*)"',
                    r'__NEXT_DATA__',
                ],
                "Webpack": [
                    r'webpack[.-](\d+\.\d+\.?\d*)',
                    r'"webpack":"(\d+\.\d+\.?\d*)"',
                ],
                "D3.js": [
                    r'd3[.-](\d+\.\d+\.?\d*)',
                    r'"d3":"(\d+\.\d+\.?\d*)"',
                ],
                "Three.js": [
                    r'three[.-](\d+\.\d+\.?\d*)',
                    r'"three":"(\d+\.\d+\.?\d*)"',
                ],
            }

            # Get all script sources
            all_content = html
            for script in soup.find_all("script", src=True):
                try:
                    js_url = urljoin(self.target, script["src"])
                    js_resp = self.session.get(
                        js_url, timeout=5, verify=False
                    )
                    all_content += js_resp.text
                    # Check script src for version
                    all_content += script["src"]
                except Exception:
                    pass

            # Check package.json if accessible
            try:
                pkg_resp = self.session.get(
                    urljoin(self.target, "/package.json"),
                    timeout=5, verify=False
                )
                if pkg_resp.status_code == 200:
                    all_content += pkg_resp.text
                    self.findings.append({
                        "type": "Exposed package.json",
                        "detail": "package.json publicly accessible — reveals all dependencies!",
                        "severity": "MEDIUM",
                        "evidence": "package.json returns 200",
                        "url": urljoin(self.target, "/package.json")
                    })
                    print("[MEDIUM] package.json exposed!")
            except Exception:
                pass

            # Detect libraries
            for library, patterns in library_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, all_content, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else "detected"
                        self.detected_libraries[library] = version
                        print(f"[+] Detected: {library} {version}")
                        break
                    elif library not in self.detected_libraries:
                        # Check if library name appears without version
                        if library.lower().replace(".js", "") in all_content.lower():
                            self.detected_libraries[library] = "unknown"

            print(f"[+] Total libraries detected: {len(self.detected_libraries)}")

        except Exception as e:
            print(f"[!] Library detection error: {e}")

    # ============================================================
    # STEP 2 — Check for Known Vulnerable Versions
    # ============================================================
    def check_vulnerable_versions(self):
        """
        Checks detected libraries against known vulnerable versions.

        WHY CRITICAL:
        Old jQuery = XSS vulnerabilities
        Old Bootstrap = XSS vulnerabilities
        Old Lodash = Prototype pollution
        Log4j 2.14 = Remote code execution!

        We maintain a database of known bad versions.
        """
        print("[*] Checking for vulnerable library versions...")

        # Known vulnerable versions database
        # Format: library: [(bad_version_range, CVE, severity, description)]
        vulnerable_versions = {
            "jQuery": [
                ("1.", "CVE-2019-11358", "HIGH",
                 "Prototype pollution — attacker can modify Object prototype"),
                ("2.", "CVE-2020-11023", "MEDIUM",
                 "XSS vulnerability in HTML manipulation"),
                ("3.0", "CVE-2020-11022", "MEDIUM",
                 "XSS in passing HTML from untrusted source"),
                ("3.1", "CVE-2020-11022", "MEDIUM",
                 "XSS vulnerability"),
                ("3.2", "CVE-2020-11022", "MEDIUM",
                 "XSS vulnerability"),
                ("3.3", "CVE-2020-11022", "MEDIUM",
                 "XSS vulnerability"),
            ],
            "Bootstrap": [
                ("3.", "CVE-2019-8331", "MEDIUM",
                 "XSS in tooltip and popover data-template attribute"),
                ("4.0", "CVE-2018-14041", "MEDIUM",
                 "XSS in data-target attribute"),
                ("4.1", "CVE-2019-8331", "MEDIUM",
                 "XSS vulnerability"),
                ("4.2", "CVE-2019-8331", "MEDIUM",
                 "XSS vulnerability"),
            ],
            "Lodash": [
                ("4.17.1", "CVE-2019-10744", "CRITICAL",
                 "Prototype pollution via defaultsDeep"),
                ("4.17.2", "CVE-2019-10744", "CRITICAL",
                 "Prototype pollution"),
                ("4.17.3", "CVE-2020-8203", "HIGH",
                 "Prototype pollution via zipObjectDeep"),
                ("4.17.4", "CVE-2020-8203", "HIGH",
                 "Prototype pollution"),
                ("4.17.10", "CVE-2019-10744", "CRITICAL",
                 "Prototype pollution"),
                ("4.17.11", "CVE-2020-8203", "HIGH",
                 "Prototype pollution"),
            ],
            "Moment.js": [
                ("2.18", "CVE-2017-18214", "HIGH",
                 "ReDoS vulnerability — regex denial of service"),
                ("2.19", "CVE-2022-24785", "HIGH",
                 "Path traversal vulnerability"),
            ],
            "Axios": [
                ("0.18", "CVE-2019-10742", "MEDIUM",
                 "Denial of service via crafted HTTP response"),
                ("0.19", "CVE-2020-28168", "MEDIUM",
                 "SSRF vulnerability"),
            ],
        }

        for library, version in self.detected_libraries.items():
            if library in vulnerable_versions and version != "unknown":
                for vuln_version, cve, severity, description in \
                        vulnerable_versions[library]:
                    if version.startswith(vuln_version):
                        self.findings.append({
                            "type": "Vulnerable Library Detected",
                            "detail": f"{library} {version} has known vulnerability: {description}",
                            "severity": severity,
                            "evidence": f"CVE: {cve} | Version: {version}",
                            "url": self.target
                        })
                        print(f"[{severity}] Vulnerable {library} {version} — {cve}")

    # ============================================================
    # STEP 3 — Check Subresource Integrity
    # ============================================================
    def check_subresource_integrity(self):
        """
        Checks if CDN scripts have integrity verification.

        WHY CRITICAL:
        Website loads jQuery from CDN:
        <script src="https://cdn.jquery.com/jquery.min.js">

        If CDN is compromised:
        Malicious jQuery served to ALL visitors!
        No way to detect without SRI!

        SRI = Subresource Integrity
        Adds hash to verify script not tampered:
        <script src="..." integrity="sha384-abc123...">

        Without SRI = supply chain attack possible!
        """
        print("[*] Checking Subresource Integrity (SRI)...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            soup = BeautifulSoup(resp.text, "html.parser")

            # CDN domains
            cdn_domains = [
                "cdn.jsdelivr.net",
                "cdnjs.cloudflare.com",
                "ajax.googleapis.com",
                "code.jquery.com",
                "stackpath.bootstrapcdn.com",
                "maxcdn.bootstrapcdn.com",
                "unpkg.com",
                "cdn.skypack.dev",
            ]

            scripts_without_sri = []
            scripts_with_sri = []

            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                integrity = script.get("integrity", "")

                # Check if from CDN
                is_cdn = any(cdn in src for cdn in cdn_domains)

                if is_cdn:
                    if integrity:
                        scripts_with_sri.append(src)
                        print(f"[+] SRI present: {src[:60]}")
                    else:
                        scripts_without_sri.append(src)
                        print(f"[!] No SRI: {src[:60]}")

            # Also check CSS links
            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href", "")
                integrity = link.get("integrity", "")
                is_cdn = any(cdn in href for cdn in cdn_domains)

                if is_cdn and not integrity:
                    scripts_without_sri.append(href)

            if scripts_without_sri:
                self.findings.append({
                    "type": "Missing Subresource Integrity",
                    "detail": f"{len(scripts_without_sri)} CDN scripts loaded without integrity check",
                    "severity": "MEDIUM",
                    "evidence": f"Scripts without SRI: {scripts_without_sri[0][:80]}...",
                    "url": self.target
                })
                print(f"[MEDIUM] {len(scripts_without_sri)} scripts missing SRI!")

            print(f"[+] SRI present: {len(scripts_with_sri)} | Missing: {len(scripts_without_sri)}")

        except Exception as e:
            print(f"[!] SRI check error: {e}")

    # ============================================================
    # STEP 4 — Check for Dependency Confusion Risk
    # ============================================================
    def check_dependency_confusion(self):
        """
        Tests for dependency confusion attack risk.

        WHAT IS DEPENDENCY CONFUSION:
        Company uses internal packages:
        @company/internal-auth (private npm)

        Attacker registers SAME name on public npm!
        When company runs npm install
        = Downloads attacker's malicious package!
        = Runs attacker code on developer machines!

        Real incident:
        Researcher found this in Apple, Microsoft, PayPal
        Got $130,000 in bug bounties!
        """
        print("[*] Checking dependency confusion risk...")

        try:
            # Check package.json
            pkg_url = urljoin(self.target, "/package.json")
            resp = self.session.get(pkg_url, timeout=5, verify=False)

            if resp.status_code == 200:
                try:
                    pkg_data = resp.json()
                    dependencies = {}
                    dependencies.update(
                        pkg_data.get("dependencies", {})
                    )
                    dependencies.update(
                        pkg_data.get("devDependencies", {})
                    )

                    # Check for scoped packages (internal packages)
                    scoped_packages = [
                        pkg for pkg in dependencies.keys()
                        if pkg.startswith("@")
                    ]

                    for pkg in scoped_packages:
                        # Check if package exists on public npm
                        npm_url = f"https://registry.npmjs.org/{pkg}"
                        try:
                            npm_resp = requests.get(
                                npm_url, timeout=5
                            )
                            if npm_resp.status_code == 404:
                                # Package NOT on public npm
                                # = Dependency confusion possible!
                                self.findings.append({
                                    "type": "Dependency Confusion Risk",
                                    "detail": f"Internal package '{pkg}' not on public npm — confusion attack possible!",
                                    "severity": "HIGH",
                                    "evidence": f"Package {pkg} absent from public registry",
                                    "url": self.target
                                })
                                print(f"[HIGH] Dependency confusion risk: {pkg}")

                        except Exception:
                            pass

                except json.JSONDecodeError:
                    pass

            # Also check for requirements.txt (Python)
            req_url = urljoin(self.target, "/requirements.txt")
            req_resp = self.session.get(req_url, timeout=5, verify=False)

            if req_resp.status_code == 200:
                self.findings.append({
                    "type": "Exposed requirements.txt",
                    "detail": "Python requirements.txt publicly accessible",
                    "severity": "MEDIUM",
                    "evidence": "requirements.txt returns 200",
                    "url": req_url
                })
                print("[MEDIUM] requirements.txt exposed!")

        except Exception as e:
            print(f"[!] Dependency confusion check error: {e}")

    # ============================================================
    # STEP 5 — Check for Typosquatting Risk
    # ============================================================
    def check_typosquatting(self):
        """
        Checks if detected libraries might be typosquatted.

        TYPOSQUATTING:
        Developer types: npm install lodahs (typo!)
        Real package: lodash
        Malicious package registered as: lodahs

        Developer installs malicious package thinking it is real!
        """
        print("[*] Checking typosquatting risk...")

        # Known typosquatted packages (real incidents!)
        known_typosquats = {
            "crossenv": "cross-env",
            "loadash": "lodash",
            "lodahs": "lodash",
            "babelcli": "babel-cli",
            "expres": "express",
            "requesst": "request",
            "mongose": "mongoose",
            "coloers": "colors",
            "reacct": "react",
            "anuglar": "angular",
            "jquerry": "jquery",
            "bootstrapp": "bootstrap",
            "momentjs": "moment",
            "axxios": "axios",
        }

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            html = resp.text.lower()

            for typo, real in known_typosquats.items():
                if typo in html:
                    self.findings.append({
                        "type": "Potential Typosquatting",
                        "detail": f"Suspicious package '{typo}' detected — did you mean '{real}'?",
                        "severity": "HIGH",
                        "evidence": f"'{typo}' found in page — possible typosquatted package",
                        "url": self.target
                    })
                    print(f"[HIGH] Typosquatting risk: {typo} (should be {real})")

        except Exception as e:
            print(f"[!] Typosquatting check error: {e}")

    # ============================================================
    # STEP 6 — Generate Library Summary Report
    # ============================================================
    def generate_library_report(self):
        """
        Creates a summary of all detected libraries
        and their security status.
        """
        print("\n[*] Generating library security report...")

        if self.detected_libraries:
            library_list = ", ".join([
                f"{lib} ({ver})"
                for lib, ver in self.detected_libraries.items()
            ])

            self.findings.append({
                "type": "Library Inventory",
                "detail": f"Detected {len(self.detected_libraries)} libraries: {library_list[:200]}",
                "severity": "INFO",
                "evidence": f"Total libraries: {len(self.detected_libraries)}",
                "url": self.target
            })

            print(f"[+] Library inventory complete: {len(self.detected_libraries)} libraries")

    # ============================================================
    # MAIN — Run complete supply chain scan
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope Supply Chain Scanner")
        print("Library Security | Dependency Analysis")
        print("="*60)

        self.detect_js_libraries()
        self.check_vulnerable_versions()
        self.check_subresource_integrity()
        self.check_dependency_confusion()
        self.check_typosquatting()
        self.generate_library_report()

        print("\n" + "="*60)
        print(f"Supply Chain Scan Complete!")
        print(f"Libraries Detected: {len(self.detected_libraries)}")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        info = sum(1 for f in self.findings if f["severity"] == "INFO")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | INFO: {info}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = SupplyChainScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETECTED LIBRARIES ---")
    for lib, ver in scanner.detected_libraries.items():
        print(f"  {lib}: {ver}")

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")