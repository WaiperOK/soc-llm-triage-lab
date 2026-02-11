from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluator import EvalCase, evaluate
from .models import Incident, Playbook
from .triage import triage_incident


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


def _load_playbooks(path: str | None) -> list[Playbook]:
    if not path:
        return list(DEFAULT_PLAYBOOKS)
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Playbook.from_dict(x) for x in payload]


def cmd_triage(ns: argparse.Namespace) -> int:
    incident_payload = json.loads(Path(ns.incident).read_text(encoding="utf-8"))
    incident = Incident.from_dict(incident_payload)
    playbooks = _load_playbooks(ns.playbooks)
    out = triage_incident(incident, playbooks, top_k=ns.top_k)
    json.dump(out.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_batch(ns: argparse.Namespace) -> int:
    playbooks = _load_playbooks(ns.playbooks)
    rows = Path(ns.incidents).read_text(encoding="utf-8").splitlines()
    results = []
    for row in rows:
        if not row.strip():
            continue
        incident = Incident.from_dict(json.loads(row))
        results.append(triage_incident(incident, playbooks).to_dict())

    out_path = Path(ns.output)
    out_path.write_text("\n".join(json.dumps(r) for r in results) + "\n", encoding="utf-8")
    print(f"wrote {len(results)} triage records to {out_path}")
    return 0


def cmd_eval(ns: argparse.Namespace) -> int:
    playbooks = _load_playbooks(ns.playbooks)
    payload = json.loads(Path(ns.dataset).read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    for row in payload:
        cases.append(
            EvalCase(
                incident=Incident.from_dict(row["incident"]),
                expected_severity=row["expected_severity"],
                expected_playbook=row["expected_playbook"],
            )
        )
    res = evaluate(cases, playbooks)
    json.dump(
        {
            "total": res.total,
            "severity_accuracy": res.severity_accuracy,
            "playbook_top1_accuracy": res.playbook_top1_accuracy,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc-llm-triage")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_triage = sub.add_parser("triage", help="Run triage for a single incident JSON")
    p_triage.add_argument("--incident", required=True)
    p_triage.add_argument("--playbooks", required=False)
    p_triage.add_argument("--top-k", type=int, default=3)
    p_triage.set_defaults(func=cmd_triage)

    p_batch = sub.add_parser("batch", help="Run triage for JSONL incidents")
    p_batch.add_argument("--incidents", required=True, help="Path to JSONL file")
    p_batch.add_argument("--output", required=True, help="Output JSONL path")
    p_batch.add_argument("--playbooks", required=False)
    p_batch.set_defaults(func=cmd_batch)

    p_eval = sub.add_parser("eval", help="Evaluate triage quality on labeled dataset")
    p_eval.add_argument("--dataset", required=True, help="Path to evaluation JSON dataset")
    p_eval.add_argument("--playbooks", required=False)
    p_eval.set_defaults(func=cmd_eval)

    ns = parser.parse_args(argv)
    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
