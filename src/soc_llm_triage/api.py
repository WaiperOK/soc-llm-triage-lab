from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .models import Incident, Playbook
from .service import TriageService
from .summarizer import LLMSummarizer


DEFAULT_PLAYBOOKS = [
    Playbook(
        name="credential-compromise",
        text="credential phishing impossible travel suspicious oauth token reset revoke sessions",
        tags=("identity", "credential", "phishing"),
    ),
    Playbook(
        name="ransomware-containment",
        text="ransomware isolate host stop lateral movement block c2 preserve forensic image",
        tags=("ransomware", "containment", "edr"),
    ),
    Playbook(
        name="data-exfiltration",
        text="exfiltration unusual egress cloud storage download dlp block rotate credentials",
        tags=("exfiltration", "network", "dlp"),
    ),
]


def make_server(
    host: str,
    port: int,
    playbooks: list[Playbook] | None = None,
    summarizer: LLMSummarizer | None = None,
) -> ThreadingHTTPServer:
    service = TriageService(playbooks or list(DEFAULT_PLAYBOOKS), summarizer=summarizer)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._json(HTTPStatus.OK, {"status": "ok"})
                return
            if self.path == "/metrics":
                body = service.metrics_text().encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/triage":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return

            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return

            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                return

            try:
                incident = Incident.from_dict(payload)
                result = service.triage(incident)
            except Exception as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_incident", "detail": str(exc)})
                return

            self._json(HTTPStatus.OK, result.to_dict())

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            # Silence access logs for deterministic test output.
            return

        def _json(self, code: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), Handler)


def run(host: str = "0.0.0.0", port: int = 8082, summarizer: LLMSummarizer | None = None) -> None:
    server = make_server(host, port, summarizer=summarizer)
    print(f"soc-llm-triage-lab api listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
