import tempfile
import unittest
from pathlib import Path

from formal_cloud.cli import main
from formal_cloud.utils import load_json


class CLITests(unittest.TestCase):
    def test_cli_compile_rego_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "compiled-rego-policy.json"
            rc = main(
                [
                    "compile",
                    "--policies",
                    "examples/policies.rego",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_cli_terraform_returns_reject_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "terraform-certificate.json"
            trace = Path(tmpdir) / "terraform-trace.jsonl"

            rc = main(
                [
                    "verify",
                    "terraform",
                    "--policies",
                    "examples/policies.yaml",
                    "--plan",
                    "examples/terraform-plan.json",
                    "--workspace",
                    "prod",
                    "--out",
                    str(out),
                    "--trace",
                    str(trace),
                ]
            )

            self.assertEqual(rc, 3)
            self.assertTrue(out.exists())
            self.assertTrue(trace.exists())

    def test_cli_attest_verify_signed_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert = Path(tmpdir) / "terraform-certificate.json"
            key = Path(tmpdir) / "signing.key"
            signed = Path(tmpdir) / "terraform-certificate-signed.json"
            report = Path(tmpdir) / "verification-report.json"
            key.write_text("test-secret-key", encoding="utf-8")

            verify_rc = main(
                [
                    "verify",
                    "terraform",
                    "--policies",
                    "examples/policies.yaml",
                    "--plan",
                    "examples/terraform-plan.json",
                    "--workspace",
                    "prod",
                    "--out",
                    str(cert),
                    "--signing-key-file",
                    str(key),
                    "--signing-key-id",
                    "ci",
                ]
            )
            self.assertEqual(verify_rc, 3)
            self.assertTrue(cert.exists())

            sign_rc = main(
                [
                    "attest",
                    "sign",
                    "--certificate",
                    str(cert),
                    "--key-file",
                    str(key),
                    "--key-id",
                    "ci",
                    "--out",
                    str(signed),
                ]
            )
            self.assertEqual(sign_rc, 0)
            self.assertTrue(signed.exists())

            attest_rc = main(
                [
                    "attest",
                    "verify",
                    "--certificate",
                    str(signed),
                    "--key-file",
                    str(key),
                    "--out",
                    str(report),
                ]
            )
            self.assertEqual(attest_rc, 0)
            self.assertTrue(report.exists())

    def test_cli_bundle_verify_and_use_in_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = Path(tmpdir) / "bundle.json"
            key = Path(tmpdir) / "bundle.key"
            cert = Path(tmpdir) / "certificate.json"
            key.write_text("bundle-test-key", encoding="utf-8")

            create_rc = main(
                [
                    "bundle",
                    "create",
                    "--bundle-id",
                    "org.formalcloud.bundle",
                    "--bundle-version",
                    "1.0.0",
                    "--policy-file",
                    "examples/policies.yaml",
                    "--out",
                    str(bundle),
                    "--signing-key-file",
                    str(key),
                    "--signing-key-id",
                    "ci",
                ]
            )
            self.assertEqual(create_rc, 0)
            self.assertTrue(bundle.exists())

            verify_bundle_rc = main(
                [
                    "bundle",
                    "verify",
                    "--bundle",
                    str(bundle),
                    "--expected-version",
                    "1.0.0",
                    "--key-file",
                    str(key),
                    "--require-signature",
                ]
            )
            self.assertEqual(verify_bundle_rc, 0)

            gate_rc = main(
                [
                    "verify",
                    "terraform",
                    "--bundle",
                    str(bundle),
                    "--bundle-version",
                    "1.0.0",
                    "--bundle-key-file",
                    str(key),
                    "--bundle-require-signature",
                    "--plan",
                    "examples/terraform-plan.json",
                    "--workspace",
                    "prod",
                    "--out",
                    str(cert),
                ]
            )
            self.assertEqual(gate_rc, 3)
            self.assertTrue(cert.exists())

    def test_cli_export_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert = Path(tmpdir) / "certificate.json"
            sarif = Path(tmpdir) / "results.sarif.json"

            verify_rc = main(
                [
                    "verify",
                    "terraform",
                    "--policies",
                    "examples/policies.yaml",
                    "--plan",
                    "examples/terraform-plan.json",
                    "--workspace",
                    "prod",
                    "--out",
                    str(cert),
                ]
            )
            self.assertEqual(verify_rc, 3)

            export_rc = main(
                [
                    "export",
                    "sarif",
                    "--certificate",
                    str(cert),
                    "--out",
                    str(sarif),
                ]
            )
            self.assertEqual(export_rc, 0)
            sarif_data = load_json(sarif)
            self.assertEqual(sarif_data.get("version"), "2.1.0")


if __name__ == "__main__":
    unittest.main()
