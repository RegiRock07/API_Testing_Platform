import requests
import re


class APITestingAgent:

    def __init__(self):
        self.base_url = "http://localhost:8001"

        # Fuzz payloads used for security testing
        self.fuzz_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "../../../../windows/system32",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "%00",
            "'; DROP TABLE users;"
        ]


    # -------------------------
    # Dynamic Fuzz Testing
    # -------------------------
    def fuzz_test(self, path, method):

        fuzz_results = []

        # find parameters like {user_id}
        params = re.findall(r"\{(.*?)\}", path)

        for payload in self.fuzz_payloads:

            fuzz_path = path

            for param in params:
                fuzz_path = fuzz_path.replace(f"{{{param}}}", payload)

            fuzz_url = self.base_url + fuzz_path

            try:
                r = requests.request(method, fuzz_url, timeout=5)

                possible_vuln = False

                if r.status_code >= 500:
                    possible_vuln = True

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

        results = []

        for ep in parsed_data["endpoints"]:

            path = ep["path"]
            method = ep["method"]

            # replace parameters with normal value for baseline test
            url_path = re.sub(r"\{.*?\}", "1", path)

            url = self.base_url + url_path

            endpoint_result = {
                "endpoint": path,
                "tests": []
            }

            # -------------------------
            # 1 Valid Request
            # -------------------------
            try:
                r = requests.request(method, url)

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
                    r = requests.request(method, invalid_url)

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
            # 3 Nonexistent Object
            # -------------------------
            if "{" in path:

                invalid_path = re.sub(r"\{.*?\}", "999999", path)
                invalid_url = self.base_url + invalid_path

                try:
                    r = requests.request(method, invalid_url)

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
                r = requests.request(wrong_method, url)

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

                endpoint_result["tests"].append({
                    "test": "dynamic_fuzz_testing",
                    "results": fuzz_results
                })


            results.append(endpoint_result)

        return {
            "agent": "api_testing",
            "status": "completed",
            "results": results
        }