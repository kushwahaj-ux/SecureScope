import requests
import socket
import re
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CloudScanner:
    """
    SecureScope Cloud Security Scanner
    =====================================
    Tests for cloud misconfigurations in AWS, Azure, GCP.

    WHY THIS MATTERS:
    Most companies now use cloud services.
    Misconfigured cloud = biggest data breach cause!

    Capital One: 100 million records from AWS S3
    Facebook: 540 million records from public S3
    These happen because of simple misconfigurations!

    Covers:
    1. AWS S3 Bucket Enumeration
    2. Azure Blob Storage Testing
    3. GCP Storage Testing
    4. Cloud Metadata Service (SSRF)
    5. Cloud Subdomain Detection
    6. Exposed Cloud Credentials
    7. Public Database Detection
    """

    def __init__(self, target_url):
        parsed = urlparse(target_url)
        self.target = target_url
        self.domain = parsed.netloc or target_url.replace(
            "https://", "").replace("http://", "").split("/")[0]
        # Extract company name from domain
        self.company_name = self.domain.split(".")[0]
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        self.findings = []
        self.cloud_provider = None
        print(f"Cloud Scanner Ready!")
        print(f"Domain: {self.domain}")
        print(f"Company: {self.company_name}")

    # ============================================================
    # STEP 1 — Detect Cloud Provider
    # ============================================================
    def detect_cloud_provider(self):
        """
        Identifies which cloud provider the target uses.
        WHY: Different clouds have different vulnerabilities!
        AWS → S3 buckets
        Azure → Blob storage
        GCP → Cloud storage buckets
        """
        print("[*] Detecting cloud provider...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )
            headers = dict(resp.headers)
            html = resp.text.lower()

            # Cloud signatures
            cloud_signatures = {
                "AWS": [
                    "amazonaws.com", "cloudfront.net",
                    "x-amz", "aws", "s3.amazonaws"
                ],
                "Azure": [
                    "azure", "azurewebsites.net",
                    "blob.core.windows.net",
                    "cloudapp.azure.com", "x-ms-"
                ],
                "GCP": [
                    "googleapis.com", "googleusercontent.com",
                    "appspot.com", "cloud.google.com",
                    "x-goog-"
                ],
                "Cloudflare": [
                    "cloudflare", "cf-ray",
                    "cloudflare-nginx"
                ]
            }

            detected = []
            for provider, signatures in cloud_signatures.items():
                for sig in signatures:
                    if (sig.lower() in html or
                            any(sig.lower() in v.lower()
                                for v in headers.values())):
                        if provider not in detected:
                            detected.append(provider)
                            print(f"[+] Cloud provider detected: {provider}")

            if detected:
                self.cloud_provider = detected[0]
                self.findings.append({
                    "type": "Cloud Provider Detected",
                    "detail": f"Target uses: {', '.join(detected)}",
                    "severity": "INFO",
                    "evidence": f"Providers: {', '.join(detected)}",
                    "url": self.target
                })

        except Exception as e:
            print(f"[!] Cloud detection error: {e}")

    # ============================================================
    # STEP 2 — AWS S3 Bucket Enumeration
    # ============================================================
    def enumerate_s3_buckets(self):
        """
        Tests for publicly accessible S3 buckets.

        WHY CRITICAL:
        S3 bucket = Amazon file storage
        If public = anyone can download ALL files!
        Customer data, source code, backups = all exposed!

        HOW WE FIND THEM:
        Companies name buckets predictably:
        companyname-backup
        companyname-uploads
        companyname-prod
        We try 50+ naming patterns!
        """
        print("[*] Enumerating S3 buckets...")

        # Common S3 bucket naming patterns
        bucket_patterns = [
            # Basic patterns
            self.company_name,
            f"{self.company_name}-backup",
            f"{self.company_name}-backups",
            f"{self.company_name}-uploads",
            f"{self.company_name}-upload",
            f"{self.company_name}-files",
            f"{self.company_name}-data",
            f"{self.company_name}-assets",
            f"{self.company_name}-static",
            f"{self.company_name}-media",
            f"{self.company_name}-images",
            f"{self.company_name}-img",
            f"{self.company_name}-prod",
            f"{self.company_name}-production",
            f"{self.company_name}-dev",
            f"{self.company_name}-development",
            f"{self.company_name}-staging",
            f"{self.company_name}-stage",
            f"{self.company_name}-test",
            f"{self.company_name}-testing",
            f"{self.company_name}-logs",
            f"{self.company_name}-log",
            f"{self.company_name}-archive",
            f"{self.company_name}-archives",
            f"{self.company_name}-bucket",
            f"{self.company_name}-storage",
            f"{self.company_name}-store",
            f"{self.company_name}-cdn",
            f"{self.company_name}-public",
            f"{self.company_name}-private",
            f"{self.company_name}-secure",
            f"{self.company_name}-config",
            f"{self.company_name}-configs",
            f"{self.company_name}-documents",
            f"{self.company_name}-docs",
            f"{self.company_name}-reports",
            f"{self.company_name}-temp",
            f"{self.company_name}-tmp",
            f"{self.company_name}-cache",
            f"{self.company_name}-api",
            f"{self.company_name}-web",
            f"{self.company_name}-app",
            f"www-{self.company_name}",
            f"api-{self.company_name}",
            f"dev-{self.company_name}",
            f"prod-{self.company_name}",
            f"staging-{self.company_name}",
            # Domain based
            self.domain.replace(".", "-"),
            self.domain.replace(".", ""),
        ]

        # S3 URL formats
        s3_formats = [
            "https://{bucket}.s3.amazonaws.com",
            "https://{bucket}.s3.ap-south-1.amazonaws.com",
            "https://s3.amazonaws.com/{bucket}",
            "https://s3.ap-south-1.amazonaws.com/{bucket}",
        ]

        found_buckets = []

        for bucket in bucket_patterns:
            for s3_format in s3_formats[:2]:
                url = s3_format.format(bucket=bucket)
                try:
                    resp = self.session.get(
                        url, timeout=5, verify=False
                    )

                    if resp.status_code == 200:
                        # Bucket is PUBLIC!
                        content_size = len(resp.text)
                        has_files = "<Key>" in resp.text or \
                                    "<Contents>" in resp.text

                        severity = "CRITICAL" if has_files else "HIGH"
                        detail = f"PUBLIC S3 bucket found: {bucket}"
                        if has_files:
                            detail += " — Contains files!"

                        if bucket not in found_buckets:
                            found_buckets.append(bucket)
                            self.findings.append({
                                "type": "Public S3 Bucket",
                                "detail": detail,
                                "severity": severity,
                                "evidence": f"URL: {url} | Status: 200 | Size: {content_size}",
                                "url": url
                            })
                            print(f"[{severity}] Public S3 bucket: {bucket}")

                    elif resp.status_code == 403:
                        # Bucket exists but private — still useful info
                        if bucket not in found_buckets:
                            found_buckets.append(bucket)
                            self.findings.append({
                                "type": "S3 Bucket Exists (Private)",
                                "detail": f"S3 bucket exists but private: {bucket}",
                                "severity": "LOW",
                                "evidence": f"403 response from {url}",
                                "url": url
                            })
                            print(f"[LOW] Private S3 bucket found: {bucket}")

                except Exception:
                    pass

        print(f"[+] S3 scan complete — {len(found_buckets)} buckets found")

    # ============================================================
    # STEP 3 — Azure Blob Storage Testing
    # ============================================================
    def enumerate_azure_blobs(self):
        """
        Tests for publicly accessible Azure Blob Storage.

        Azure equivalent of S3 buckets.
        Many Indian companies use Azure (Microsoft partnership).
        Same misconfiguration issues as S3!
        """
        print("[*] Testing Azure Blob Storage...")

        azure_patterns = [
            f"https://{self.company_name}.blob.core.windows.net",
            f"https://{self.company_name}storage.blob.core.windows.net",
            f"https://{self.company_name}data.blob.core.windows.net",
            f"https://{self.company_name}backup.blob.core.windows.net",
            f"https://{self.company_name}files.blob.core.windows.net",
            f"https://{self.company_name}media.blob.core.windows.net",
            f"https://{self.company_name}assets.blob.core.windows.net",
            f"https://{self.company_name}cdn.blob.core.windows.net",
        ]

        # Common container names
        containers = [
            "public", "uploads", "files", "media",
            "backup", "data", "assets", "images",
            "documents", "reports", "logs"
        ]

        for base_url in azure_patterns:
            try:
                # Check if storage account exists
                resp = self.session.get(
                    base_url, timeout=5, verify=False
                )

                if resp.status_code in [200, 400, 403, 409]:
                    print(f"[+] Azure storage found: {base_url}")

                    # Test public containers
                    for container in containers:
                        container_url = f"{base_url}/{container}"
                        try:
                            c_resp = self.session.get(
                                container_url + "?restype=container&comp=list",
                                timeout=5, verify=False
                            )

                            if c_resp.status_code == 200:
                                self.findings.append({
                                    "type": "Public Azure Blob Container",
                                    "detail": f"Azure container publicly accessible: {container}",
                                    "severity": "CRITICAL",
                                    "evidence": f"URL: {container_url}",
                                    "url": container_url
                                })
                                print(f"[CRITICAL] Public Azure container: {container_url}")

                        except Exception:
                            pass

            except Exception:
                pass

    # ============================================================
    # STEP 4 — GCP Storage Testing
    # ============================================================
    def enumerate_gcp_storage(self):
        """
        Tests for publicly accessible Google Cloud Storage.
        Same concept as S3 and Azure Blob!
        """
        print("[*] Testing GCP Cloud Storage...")

        gcp_patterns = [
            f"https://storage.googleapis.com/{self.company_name}",
            f"https://storage.googleapis.com/{self.company_name}-backup",
            f"https://storage.googleapis.com/{self.company_name}-uploads",
            f"https://storage.googleapis.com/{self.company_name}-data",
            f"https://storage.googleapis.com/{self.company_name}-public",
            f"https://{self.company_name}.storage.googleapis.com",
        ]

        for url in gcp_patterns:
            try:
                resp = self.session.get(url, timeout=5, verify=False)

                if resp.status_code == 200:
                    self.findings.append({
                        "type": "Public GCP Storage Bucket",
                        "detail": f"Google Cloud Storage bucket publicly accessible",
                        "severity": "CRITICAL",
                        "evidence": f"URL: {url} returned 200",
                        "url": url
                    })
                    print(f"[CRITICAL] Public GCP bucket: {url}")

            except Exception:
                pass

    # ============================================================
    # STEP 5 — Cloud Metadata Service Testing
    # ============================================================
    def check_cloud_metadata(self):
        """
        Tests if cloud metadata service is accessible via SSRF.

        WHY CRITICAL:
        Every cloud server has metadata URL:
        AWS:   http://169.254.169.254/latest/meta-data/
        Azure: http://169.254.169.254/metadata/instance
        GCP:   http://metadata.google.internal/

        Contains AWS credentials, IAM roles, secrets!
        Capital One breach used exactly this!
        """
        print("[*] Testing cloud metadata access...")

        metadata_urls = [
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",

            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

            # GCP metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        ]

        # SSRF test parameters
        ssrf_params = [
            "url", "redirect", "proxy", "fetch",
            "image", "src", "href", "link"
        ]

        for metadata_url in metadata_urls[:3]:
            for param in ssrf_params[:3]:
                test_url = f"{self.target}?{param}={metadata_url}"
                try:
                    resp = self.session.get(
                        test_url, timeout=5, verify=False
                    )

                    # Check for AWS metadata indicators
                    aws_indicators = [
                        "ami-id", "instance-id",
                        "security-credentials",
                        "AccessKeyId", "SecretAccessKey"
                    ]

                    if any(ind in resp.text for ind in aws_indicators):
                        self.findings.append({
                            "type": "Cloud Metadata SSRF",
                            "detail": f"AWS metadata accessible via SSRF — credentials exposed!",
                            "severity": "CRITICAL",
                            "evidence": f"Metadata URL accessible via {param} parameter",
                            "url": test_url
                        })
                        print(f"[CRITICAL] Cloud metadata SSRF via {param}!")

                except Exception:
                    pass

    # ============================================================
    # STEP 6 — Cloud Subdomain Detection
    # ============================================================
    def find_cloud_subdomains(self):
        """
        Finds cloud-hosted subdomains.

        WHY:
        Companies host services on cloud subdomains:
        app.company.com → Azure App Service
        api.company.com → AWS EC2
        cdn.company.com → CloudFront

        These often have weaker security than main site!
        """
        print("[*] Finding cloud subdomains...")

        cloud_subdomain_patterns = [
            # AWS
            f"{self.company_name}.cloudfront.net",
            f"{self.company_name}.elasticbeanstalk.com",
            f"{self.company_name}.execute-api.ap-south-1.amazonaws.com",

            # Azure
            f"{self.company_name}.azurewebsites.net",
            f"{self.company_name}.azurecontainer.io",
            f"{self.company_name}.trafficmanager.net",

            # GCP
            f"{self.company_name}.appspot.com",
            f"{self.company_name}.run.app",
            f"{self.company_name}.cloudfunctions.net",

            # Generic cloud
            f"{self.company_name}.herokuapp.com",
            f"{self.company_name}.netlify.app",
            f"{self.company_name}.vercel.app",
            f"{self.company_name}.github.io",
        ]

        for subdomain in cloud_subdomain_patterns:
            try:
                ip = socket.gethostbyname(subdomain)
                url = f"https://{subdomain}"

                try:
                    resp = self.session.get(
                        url, timeout=5, verify=False
                    )

                    if resp.status_code in [200, 301, 302, 403]:
                        self.findings.append({
                            "type": "Cloud Subdomain Found",
                            "detail": f"Cloud-hosted subdomain: {subdomain}",
                            "severity": "MEDIUM",
                            "evidence": f"IP: {ip} | Status: {resp.status_code}",
                            "url": url
                        })
                        print(f"[MEDIUM] Cloud subdomain: {subdomain}")

                except Exception:
                    pass

            except socket.gaierror:
                pass

    # ============================================================
    # STEP 7 — Check Exposed Cloud Credentials
    # ============================================================
    def check_exposed_cloud_credentials(self):
        """
        Scans website for accidentally exposed cloud credentials.

        WHY CRITICAL:
        Developers put cloud keys in:
        - JavaScript files
        - HTML comments
        - Config files

        Hacker finds = full cloud access!
        """
        print("[*] Checking for exposed cloud credentials...")

        try:
            resp = self.session.get(
                self.target, timeout=10, verify=False
            )

            cloud_credential_patterns = {
                "AWS Access Key": r'AKIA[0-9A-Z]{16}',
                "AWS Secret Key": r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
                "Azure Connection String": r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
                "Azure SAS Token": r'sv=\d{4}-\d{2}-\d{2}&ss=',
                "GCP Service Account": r'"type":\s*"service_account"',
                "GCP API Key": r'AIza[0-9A-Za-z\-_]{35}',
                "AWS Account ID": r'\b\d{12}\b(?=.*aws)',
                "S3 Bucket ARN": r'arn:aws:s3:::[a-z0-9\-]+',
            }

            for cred_type, pattern in cloud_credential_patterns.items():
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self.findings.append({
                        "type": "Exposed Cloud Credential",
                        "detail": f"{cred_type} found in page source!",
                        "severity": "CRITICAL",
                        "evidence": f"Pattern matched: {cred_type}",
                        "url": self.target
                    })
                    print(f"[CRITICAL] {cred_type} exposed!")

        except Exception as e:
            print(f"[!] Credential check error: {e}")

    # ============================================================
    # STEP 8 — Public Database Detection
    # ============================================================
    def check_public_databases(self):
        """
        Checks if cloud databases are publicly accessible.

        WHY CRITICAL:
        Developers misconfigure RDS/CloudSQL as public
        Database port open to entire internet!
        Anyone can attempt to connect!

        Common ports:
        3306 = MySQL/MariaDB
        5432 = PostgreSQL
        27017 = MongoDB
        6379 = Redis
        9200 = Elasticsearch
        """
        print("[*] Checking for public cloud databases...")

        # Resolve target IP
        try:
            target_ip = socket.gethostbyname(self.domain)
        except Exception:
            return

        # Common cloud database ports
        database_ports = {
            3306: "MySQL/MariaDB",
            5432: "PostgreSQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch",
            9300: "Elasticsearch (cluster)",
            5984: "CouchDB",
            8086: "InfluxDB",
            7474: "Neo4j",
        }

        for port, db_name in database_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                sock.close()

                if result == 0:
                    self.findings.append({
                        "type": "Public Database Port",
                        "detail": f"{db_name} port {port} open on cloud server",
                        "severity": "CRITICAL",
                        "evidence": f"Port {port} ({db_name}) accessible from internet",
                        "url": f"{target_ip}:{port}"
                    })
                    print(f"[CRITICAL] {db_name} port {port} is PUBLIC!")

            except Exception:
                pass

    # ============================================================
    # MAIN — Run complete cloud security scan
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope Cloud Security Scanner")
        print("AWS | Azure | GCP Coverage")
        print("="*60)

        self.detect_cloud_provider()
        self.enumerate_s3_buckets()
        self.enumerate_azure_blobs()
        self.enumerate_gcp_storage()
        self.check_cloud_metadata()
        self.find_cloud_subdomains()
        self.check_exposed_cloud_credentials()
        self.check_public_databases()

        print("\n" + "="*60)
        print(f"Cloud Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")
        info = sum(1 for f in self.findings if f["severity"] == "INFO")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low} | INFO: {info}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = CloudScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")