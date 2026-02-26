import tempfile
import unittest
from pathlib import Path

from formal_cloud.cli import main


class CLITests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
