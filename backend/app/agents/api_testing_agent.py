import requests
import re


class APITestingAgent:

    def __init__(self, base_url=None):
        # FIX #2: base_url is now configurable, not hardcoded
        self.base_url = base_url or "http://localhost:8001"

        # Fuzz payloads used for security testing
        self.fuzz_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "../../../../windows/system32",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "%00",
            "'; DROP TABLE users;",
            "{{7*7}}",           # SSTI
            "${7*7}",            # EL injection
            "null",
            "-1",
            "0",
        ]

    def fuzz_test(self, path, method):

        fuzz_results = []
        params = re.findall(r"\{(.*?)\}", path)

        for payload in self.fuzz_payloads:
            fuzz_path = path
            for param in params:
                fuzz_path = fuzz_path.replace(f"{{{param}}}", payload)

            fuzz_url = self.base_url + fuzz_path

            try:
                r = requests.request(method, fuzz_url, timeout=5)
                possible_vuln = r.status_code >= 500

                fuzz_results.append({
                    "payload": payload,
                    "url": fuzz_url,
                    "status_code": r.status_code,
                    "possible_vulnerability": possible_vuln
                })

            except Exception as e:
                fuzz_results.append({
                    "payload": payload,
                    "url": fuzz_url,
                    "error": str(e),
                    "possible_vulnerability": True
                })

        return fuzz_results

    def run(self, parsed_data):

        # FIX #2: pick up base_url from parsed_data if provided (set by URL scan)
        if "base_url" in parsed_data:
            self.base_url = parsed_data["base_url"]

        results = []

        for ep in parsed_data["endpoints"]:

            path = ep["path"]
            method = ep["method"]

            url_path = re.sub(r"\{.*?\}", "1", path)
            url = self.base_url + url_path

            endpoint_result = {
                "endpoint": path,
                "method": method,
                "base_url": self.base_url,
                "tests": []
            }

            # -------------------------
            # 1 Valid Request
            # -------------------------
            try:
                r = requests.request(method, url, timeout=5)
                endpoint_result["tests"].append({
                    "test": "valid_request",
                    "status_code": r.status_code,
                    "passed": r.status_code < 400
                })
            except Exception as e:
                endpoint_result["tests"].append({
                    "test": "valid_request",
                    "error": str(e),
                    "passed": False
                })

            # -------------------------
            # 2 Invalid Parameter
            # -------------------------
            if "{" in path:
                invalid_path = re.sub(r"\{.*?\}", "abc", path)
                invalid_url = self.base_url + invalid_path

                try:
                    r = requests.request(method, invalid_url, timeout=5)
                    endpoint_result["tests"].append({
                        "test": "invalid_parameter",
                        "status_code": r.status_code,
                        "passed": r.status_code >= 400
                    })
                except Exception as e:
                    endpoint_result["tests"].append({
                        "test": "invalid_parameter",
                        "error": str(e),
                        "passed": False
                    })

            # -------------------------
            # 3 Nonexistent Resource
            # -------------------------
            if "{" in path:
                invalid_path = re.sub(r"\{.*?\}", "999999", path)
                invalid_url = self.base_url + invalid_path

                try:
                    r = requests.request(method, invalid_url, timeout=5)
                    endpoint_result["tests"].append({
                        "test": "nonexistent_resource",
                        "status_code": r.status_code,
                        "passed": r.status_code == 404
                    })
                except Exception as e:
                    endpoint_result["tests"].append({
                        "test": "nonexistent_resource",
                        "error": str(e),
                        "passed": False
                    })

            # -------------------------
            # 4 Wrong HTTP Method
            # -------------------------
            wrong_method = "POST" if method != "POST" else "GET"

            try:
                r = requests.request(wrong_method, url, timeout=5)
                endpoint_result["tests"].append({
                    "test": "wrong_method",
                    "status_code": r.status_code,
                    "passed": r.status_code in [400, 405]
                })
            except Exception as e:
                endpoint_result["tests"].append({
                    "test": "wrong_method",
                    "error": str(e),
                    "passed": False
                })

            # -------------------------
            # 5 Dynamic Fuzz Testing
            # -------------------------
            if "{" in path:
                fuzz_results = self.fuzz_test(path, method)
                vulnerable_payloads = [f for f in fuzz_results if f.get("possible_vulnerability")]

                endpoint_result["tests"].append({
                    "test": "dynamic_fuzz_testing",
                    "total_payloads": len(fuzz_results),
                    "vulnerable_count": len(vulnerable_payloads),
                    "passed": len(vulnerable_payloads) == 0,
                    "results": fuzz_results
                })

            results.append(endpoint_result)

        return {
            "agent": "api_testing",
            "status": "completed",
            "base_url_tested": self.base_url,
            "results": results
        }