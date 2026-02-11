import json
import threading
import unittest
from urllib import request

from soc_llm_triage.api import make_server


class TestAPI(unittest.TestCase):
    def test_triage_endpoint_and_metrics(self) -> None:
        server = make_server("127.0.0.1", 0)
        host, port = server.server_address

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            payload = {
                "title": "Credential abuse",
                "description": "Credential phishing with token theft",
                "source": "identity",
                "asset_criticality": 4,
                "internet_exposed": True,
            }
            req = request.Request(
                f"http://{host}:{port}/v1/triage",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req) as resp:  # noqa: S310
                body = json.loads(resp.read().decode("utf-8"))
                self.assertIn(body["severity"], {"high", "critical"})

            with request.urlopen(f"http://{host}:{port}/metrics") as resp:  # noqa: S310
                metrics = resp.read().decode("utf-8")
                self.assertIn("soc_triage_requests_total", metrics)
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
