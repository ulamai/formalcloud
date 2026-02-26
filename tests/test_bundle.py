import tempfile
import unittest
from pathlib import Path

from formal_cloud.bundle import (
    create_policy_bundle,
    load_compiled_policy_from_bundle,
    verify_policy_bundle,
)
from formal_cloud.trace import TraceLogger
from formal_cloud.utils import write_json


class BundleTests(unittest.TestCase):
    def test_create_verify_and_load_bundle(self) -> None:
        bundle = create_policy_bundle(
            policy_files=[Path("examples/policies.yaml"), Path("examples/policies.rego")],
            bundle_id="org.formalcloud.bundle",
            bundle_version="1.0.0",
            key=b"bundle-secret",
            key_id="ci",
            trace=TraceLogger(None),
        )

        report = verify_policy_bundle(
            bundle=bundle,
            key=b"bundle-secret",
            expected_version="1.0.0",
            require_signature=True,
        )
        self.assertTrue(report["valid"])

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_path = Path(tmpdir) / "bundle.json"
            write_json(bundle_path, bundle)

            compiled = load_compiled_policy_from_bundle(
                bundle_path=bundle_path,
                policy_set_id="org.baseline.cloud-security",
                expected_bundle_version="1.0.0",
                key=b"bundle-secret",
                require_signature=True,
                trace=TraceLogger(None),
            )
            self.assertEqual(compiled.policy_set_id, "org.baseline.cloud-security")
            self.assertEqual(len(compiled.rules), 7)

    def test_bundle_version_pin_failure(self) -> None:
        bundle = create_policy_bundle(
            policy_files=[Path("examples/policies.yaml")],
            bundle_id="org.formalcloud.bundle",
            bundle_version="1.2.3",
            key=None,
            key_id="local",
            trace=TraceLogger(None),
        )

        report = verify_policy_bundle(
            bundle=bundle,
            key=None,
            expected_version="9.9.9",
            require_signature=False,
        )
        self.assertFalse(report["valid"])


if __name__ == "__main__":
    unittest.main()
