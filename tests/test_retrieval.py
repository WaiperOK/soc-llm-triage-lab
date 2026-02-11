import unittest

from soc_llm_triage.models import Playbook
from soc_llm_triage.retrieval import rank_playbooks


class TestRetrievalRanking(unittest.TestCase):
    def test_ransomware_is_ranked_first(self) -> None:
        playbooks = [
            Playbook("credential-compromise", "revoke sessions rotate credentials mfa"),
            Playbook("ransomware-containment", "ransomware isolate host block c2 stop lateral movement", ("ransomware",)),
        ]
        ranked = rank_playbooks(
            "Ransomware detected with lateral movement and C2 traffic",
            incident_tags=["ransomware", "edr"],
            playbooks=playbooks,
        )
        self.assertEqual(ranked[0].playbook.name, "ransomware-containment")


if __name__ == "__main__":
    unittest.main()
