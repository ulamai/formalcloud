import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file


class StarterPolicyPacksTests(unittest.TestCase):
    def test_starter_policy_packs_compile(self) -> None:
        pack_files = sorted(Path("examples/policy-packs").glob("*-starter.yaml"))
        self.assertGreaterEqual(len(pack_files), 3)

        for pack in pack_files:
            compiled = compile_policy_file(pack)
            self.assertGreater(len(compiled.rules), 0, f"empty rules in {pack}")
            self.assertTrue(compiled.policy_set_id.startswith("org.formalcloud.pack."))


if __name__ == "__main__":
    unittest.main()
