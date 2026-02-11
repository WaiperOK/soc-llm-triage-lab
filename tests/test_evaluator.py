import unittest

from soc_llm_triage.evaluator import EvalCase, evaluate
from soc_llm_triage.models import Incident, Playbook


class TestEvaluator(unittest.TestCase):
    def test_evaluate_metrics(self) -> None:
        playbooks = [
            Playbook("credential-compromise", "credential phishing reset mfa"),
            Playbook("ransomware-containment", "ransomware isolate host c2"),
        ]

        cases = [
            EvalCase(
                incident=Incident(
                    title="Credential theft",
                    description="Credential phishing and suspicious oauth token",
                    source="identity",
                    asset_criticality=4,
                    internet_exposed=True,
                ),
                expected_severity="high",
                expected_playbook="credential-compromise",
            ),
            EvalCase(
                incident=Incident(
                    title="Ransomware on domain controller",
                    description="Ransomware with c2 and lateral movement",
                    source="edr",
                    asset_criticality=5,
                    internet_exposed=True,
                ),
                expected_severity="critical",
                expected_playbook="ransomware-containment",
            ),
        ]

        res = evaluate(cases, playbooks)
        self.assertEqual(res.total, 2)
        self.assertGreaterEqual(res.playbook_top1_accuracy, 0.5)


if __name__ == "__main__":
    unittest.main()
