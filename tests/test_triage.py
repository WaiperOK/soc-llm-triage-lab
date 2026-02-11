import unittest

from soc_llm_triage.retrieval import Playbook
from soc_llm_triage.triage import Incident, triage_incident


class TestTriage(unittest.TestCase):
    def test_ransomware_incident_becomes_high(self) -> None:
        incident = Incident(
            title="Potential ransomware",
            description="Host shows ransomware and exfiltration behavior",
            source="siem",
            asset_criticality=5,
            internet_exposed=True,
        )
        pbs = [
            Playbook("credential-compromise", "credential reset mfa"),
            Playbook("ransomware-containment", "ransomware isolate backup"),
        ]
        result = triage_incident(incident, pbs)
        self.assertIn(result.severity, {"high", "critical"})
        self.assertEqual(result.recommended_playbook, "ransomware-containment")


if __name__ == "__main__":
    unittest.main()
