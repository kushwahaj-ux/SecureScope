import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GraphQLScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json"
        }
        self.findings = []
        self.graphql_url = None
        print(f"GraphQL Scanner Ready! Target: {self.target}")

    # ============================================================
    # STEP 1 — Find GraphQL endpoint
    # ============================================================
    def find_graphql_endpoint(self):
        """
        Tries common GraphQL endpoint paths.
        WHY: GraphQL endpoint is the gateway to entire API
        Finding it = finding the master key to all data
        """
        print("[*] Searching for GraphQL endpoint...")

        common_paths = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/query",
            "/api/query",
            "/gql",
            "/api",
        ]

        for path in common_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                # Send simple introspection query
                resp = self.session.post(
                    url,
                    json={"query": "{ __typename }"},
                    timeout=5,
                    verify=False
                )
                if resp.status_code in [200, 400] and (
                    "data" in resp.text or
                    "errors" in resp.text or
                    "graphql" in resp.text.lower()
                ):
                    self.graphql_url = url
                    print(f"[+] GraphQL endpoint found: {url}")
                    return True
            except Exception:
                pass

        print("[!] No GraphQL endpoint found")
        return False

    # ============================================================
    # STEP 2 — Test Introspection
    # ============================================================
    def check_introspection(self):
        """
        Tests if GraphQL introspection is enabled.
        WHY: Introspection reveals entire API schema —
        every query, mutation, type and field.
        Like getting the complete blueprint of a building.
        Disabled in production = good security practice.
        Enabled = hacker can map entire API in seconds.
        """
        if not self.graphql_url:
            return

        print("[*] Testing GraphQL introspection...")

        introspection_query = """
        {
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                    }
                }
            }
        }
        """

        try:
            resp = self.session.post(
                self.graphql_url,
                json={"query": introspection_query},
                timeout=10,
                verify=False
            )

            if resp.status_code == 200 and "__schema" in resp.text:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                user_types = [t for t in types if not t["name"].startswith("__")]

                self.findings.append({
                    "type": "GraphQL Introspection Enabled",
                    "detail": f"Full API schema exposed at {self.graphql_url} — {len(user_types)} types found",
                    "severity": "HIGH",
                    "evidence": f"Types exposed: {', '.join([t['name'] for t in user_types[:5]])}...",
                    "url": self.graphql_url
                })
                print(f"[HIGH] Introspection enabled! {len(user_types)} types exposed!")
                return user_types

            else:
                print("[+] Introspection disabled — good security practice!")

        except Exception as e:
            print(f"[!] Introspection test error: {e}")

        return []

    # ============================================================
    # STEP 3 — Test for Batch Attack vulnerability
    # ============================================================
    def check_batch_attack(self):
        """
        Tests if GraphQL allows batched queries.
        WHY: Batching = sending 100 login attempts in 1 request
        Bypasses rate limiting completely!
        Normal rate limit: 5 requests per minute
        With batching: 500 attempts in 1 request — same as 1 request!
        """
        if not self.graphql_url:
            return

        print("[*] Testing GraphQL batch attack...")

        # Send 10 queries in one request
        batch_query = [
            {"query": "{ __typename }"}
            for _ in range(10)
        ]

        try:
            resp = self.session.post(
                self.graphql_url,
                json=batch_query,
                timeout=10,
                verify=False
            )

            if resp.status_code == 200 and isinstance(resp.json(), list):
                self.findings.append({
                    "type": "GraphQL Batch Attack Possible",
                    "detail": f"GraphQL accepts batched queries at {self.graphql_url}",
                    "severity": "HIGH",
                    "evidence": f"Server processed {len(resp.json())} batched queries in 1 request",
                    "url": self.graphql_url
                })
                print(f"[HIGH] Batch attack possible! Server accepted 10 queries in 1 request!")
            else:
                print("[+] Batch queries rejected — good!")

        except Exception as e:
            print(f"[!] Batch test error: {e}")

    # ============================================================
    # STEP 4 — Test for Field Suggestions (Information Disclosure)
    # ============================================================
    def check_field_suggestions(self):
        """
        Tests if GraphQL reveals field names in error messages.
        WHY: Even without introspection, GraphQL sometimes
        suggests correct field names when you type wrong ones.
        Like a lock that tells you when you are getting warmer!
        """
        if not self.graphql_url:
            return

        print("[*] Testing GraphQL field suggestions...")

        test_query = '{ doesNotExist }'

        try:
            resp = self.session.post(
                self.graphql_url,
                json={"query": test_query},
                timeout=5,
                verify=False
            )

            if "Did you mean" in resp.text or "suggestion" in resp.text.lower():
                self.findings.append({
                    "type": "GraphQL Field Suggestions Enabled",
                    "detail": "GraphQL reveals field names in error messages",
                    "severity": "MEDIUM",
                    "evidence": "Error message contains field name suggestions",
                    "url": self.graphql_url
                })
                print("[MEDIUM] Field suggestions enabled — reveals API structure!")
            else:
                print("[+] Field suggestions disabled — good!")

        except Exception as e:
            print(f"[!] Field suggestion test error: {e}")

    # ============================================================
    # STEP 5 — Test for Depth Limit (DoS vulnerability)
    # ============================================================
    def check_depth_limit(self):
        """
        Tests if GraphQL has query depth limiting.
        WHY: Without depth limit, attacker sends deeply nested query
        Server tries to resolve it — crashes from memory exhaustion
        This is a Denial of Service attack specific to GraphQL
        """
        if not self.graphql_url:
            return

        print("[*] Testing GraphQL depth limit...")

        # Create deeply nested query
        deep_query = "{ __typename " * 10 + "}" * 10

        try:
            resp = self.session.post(
                self.graphql_url,
                json={"query": deep_query},
                timeout=10,
                verify=False
            )

            if resp.status_code == 200 and "data" in resp.text:
                self.findings.append({
                    "type": "GraphQL No Depth Limiting",
                    "detail": "GraphQL accepts deeply nested queries — DoS attack possible",
                    "severity": "MEDIUM",
                    "evidence": "Nested query depth of 10 accepted without restriction",
                    "url": self.graphql_url
                })
                print("[MEDIUM] No depth limit — DoS attack possible!")
            else:
                print("[+] Depth limiting enabled — good!")

        except Exception as e:
            print(f"[!] Depth limit test error: {e}")

    # ============================================================
    # MAIN — Run complete GraphQL analysis
    # ============================================================
    def run_full_scan(self):
        print("\n" + "="*60)
        print("SecureScope GraphQL Scanner")
        print("="*60)

        # Find endpoint first
        found = self.find_graphql_endpoint()

        if not found:
            print("[!] No GraphQL endpoint found — skipping GraphQL tests")
            return self.findings

        # Run all checks
        self.check_introspection()
        self.check_batch_attack()
        self.check_field_suggestions()
        self.check_depth_limit()

        print("\n" + "="*60)
        print(f"GraphQL Scan Complete!")
        print(f"Total Findings: {len(self.findings)}")

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
        print("="*60)

        return self.findings


if __name__ == "__main__":
    scanner = GraphQLScanner("https://sharpener.tech")
    findings = scanner.run_full_scan()

    print("\n--- DETAILED FINDINGS ---")
    for f in findings:
        print(f"\n[{f['severity']}] {f['type']}")
        print(f"  Detail  : {f['detail']}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:80]}")
        print(f"  URL     : {f['url'][:80]}")