from __future__ import annotations

import argparse
import json
import sys

from .retrieval import Playbook
from .triage import Incident, triage_incident


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc-llm-triage")
    parser.add_argument("--incident", required=True, help="Path to incident JSON")
    ns = parser.parse_args(argv)

    with open(ns.incident, "r", encoding="utf-8") as f:
        payload = json.load(f)

    incident = Incident(
        title=payload["title"],
        description=payload["description"],
        source=payload.get("source", "unknown"),
        asset_criticality=int(payload.get("asset_criticality", 3)),
        internet_exposed=bool(payload.get("internet_exposed", False)),
    )
    playbooks = [
        Playbook("credential-compromise", "credential phishing mfa reset revoke sessions"),
        Playbook("ransomware-containment", "ransomware isolate host stop lateral movement backup"),
        Playbook("data-exfiltration", "exfiltration network egress block credentials rotate"),
    ]
    result = triage_incident(incident, playbooks)
    json.dump(result.__dict__, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
