import unittest
from pathlib import Path

from formal_cloud.ir_diff import diff_compiled_policies
from formal_cloud.policy import compile_policy_file
from formal_cloud.replay import replay_check


class ReplayAndDiffTests(unittest.TestCase):
    def test_policy_diff_no_change_for_same_input(self) -> None:
        left = compile_policy_file(Path("examples/policies.yaml"))
        right = compile_policy_file(Path("examples/policies.yaml"))
        diff = diff_compiled_policies(left, right)

        self.assertTrue(diff["compatible"])
        self.assertEqual(diff["rules"]["added"], [])
        self.assertEqual(diff["rules"]["removed"], [])
        self.assertEqual(diff["rules"]["changed"], [])
        self.assertEqual(diff["exceptions"]["added"], [])
        self.assertEqual(diff["exceptions"]["removed"], [])
        self.assertEqual(diff["exceptions"]["changed"], [])

    def test_replay_check_detects_mismatch(self) -> None:
        expected = {
            "certificate_id": "abc",
            "decision": "accept",
            "policy": {"policy_digest": "p1"},
            "subject": {"digest": "s1"},
        }
        replayed = {
            "certificate_id": "def",
            "decision": "reject",
            "policy": {"policy_digest": "p2"},
            "subject": {"digest": "s2"},
        }
        report = replay_check(expected_certificate=expected, replayed_certificate=replayed)
        self.assertFalse(report["valid"])
        failed = [check["name"] for check in report["checks"] if not check["ok"]]
        self.assertCountEqual(
            failed,
            ["certificate_id", "decision", "policy_digest", "subject_digest"],
        )


if __name__ == "__main__":
    unittest.main()
