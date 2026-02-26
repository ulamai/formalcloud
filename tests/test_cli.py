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

    def test_cli_policy_diff_and_fail_on_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_json = Path(tmpdir) / "diff.json"
            rc = main(
                [
                    "policy",
                    "diff",
                    "--left",
                    "examples/policies.yaml",
                    "--right",
                    "examples/policies-with-exceptions.yaml",
                    "--out",
                    str(diff_json),
                ]
            )
            self.assertEqual(rc, 0)
            diff = load_json(diff_json)
            self.assertTrue(diff["rules"]["removed"])
            self.assertEqual(diff["exceptions"]["added"], ["EXC-TF001-PUBLIC-ASSETS"])

            fail_rc = main(
                [
                    "policy",
                    "diff",
                    "--left",
                    "examples/policies.yaml",
                    "--right",
                    "examples/policies-with-exceptions.yaml",
                    "--out",
                    str(diff_json),
                    "--fail-on-diff",
                ]
            )
            self.assertEqual(fail_rc, 8)

    def test_cli_replay_and_extended_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert = Path(tmpdir) / "certificate.json"
            trace = Path(tmpdir) / "trace.jsonl"
            replay_report = Path(tmpdir) / "replay-report.json"
            junit = Path(tmpdir) / "results.junit.xml"
            checks = Path(tmpdir) / "checks.json"
            intoto = Path(tmpdir) / "statement.intoto.json"
            pack_dir = Path(tmpdir) / "evidence-pack"

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
                    "--trace",
                    str(trace),
                    "--out",
                    str(cert),
                ]
            )
            self.assertEqual(verify_rc, 3)

            replay_rc = main(
                [
                    "replay",
                    "terraform",
                    "--policies",
                    "examples/policies.yaml",
                    "--plan",
                    "examples/terraform-plan.json",
                    "--workspace",
                    "prod",
                    "--expected-certificate",
                    str(cert),
                    "--out",
                    str(replay_report),
                ]
            )
            self.assertEqual(replay_rc, 0)
            self.assertTrue(load_json(replay_report)["valid"])

            junit_rc = main(
                [
                    "export",
                    "junit",
                    "--certificate",
                    str(cert),
                    "--out",
                    str(junit),
                    "--include-waived",
                ]
            )
            self.assertEqual(junit_rc, 0)
            self.assertIn("<testsuite", junit.read_text(encoding="utf-8"))

            checks_rc = main(
                [
                    "export",
                    "github-checks",
                    "--certificate",
                    str(cert),
                    "--out",
                    str(checks),
                ]
            )
            self.assertEqual(checks_rc, 0)
            checks_payload = load_json(checks)
            self.assertEqual(checks_payload["conclusion"], "failure")

            intoto_rc = main(
                [
                    "export",
                    "intoto",
                    "--certificate",
                    str(cert),
                    "--out",
                    str(intoto),
                ]
            )
            self.assertEqual(intoto_rc, 0)
            intoto_statement = load_json(intoto)
            self.assertEqual(intoto_statement["_type"], "https://in-toto.io/Statement/v1")

            evidence_rc = main(
                [
                    "export",
                    "evidence-pack",
                    "--certificate",
                    str(cert),
                    "--trace",
                    str(trace),
                    "--extra-file",
                    "examples/policies.yaml",
                    "--out-dir",
                    str(pack_dir),
                ]
            )
            self.assertEqual(evidence_rc, 0)
            manifest = load_json(pack_dir / "manifest.json")
            self.assertGreaterEqual(len(manifest["files"]), 3)
            self.assertEqual(manifest["certificate_id"], load_json(cert)["certificate_id"])

    def test_cli_kubernetes_changed_files_fast_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changed = Path(tmpdir) / "changed-files.txt"
            changed.write_text("examples/k8s-manifest.yaml\n", encoding="utf-8")

            cert = Path(tmpdir) / "k8s-certificate.json"
            rc = main(
                [
                    "verify",
                    "kubernetes",
                    "--policies",
                    "examples/policies.yaml",
                    "--manifest-dir",
                    ".",
                    "--changed-files-file",
                    str(changed),
                    "--out",
                    str(cert),
                ]
            )
            self.assertEqual(rc, 3)
            self.assertEqual(load_json(cert)["decision"], "reject")

            changed.write_text("README.md\n", encoding="utf-8")
            empty_cert = Path(tmpdir) / "k8s-empty-certificate.json"
            empty_rc = main(
                [
                    "verify",
                    "kubernetes",
                    "--policies",
                    "examples/policies.yaml",
                    "--manifest-dir",
                    ".",
                    "--changed-files-file",
                    str(changed),
                    "--out",
                    str(empty_cert),
                ]
            )
            self.assertEqual(empty_rc, 0)
            empty_data = load_json(empty_cert)
            self.assertEqual(empty_data["decision"], "accept")
            self.assertEqual(empty_data["subject"]["metadata"]["resource_count"], 0)

    def test_cli_replay_kubernetes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert = Path(tmpdir) / "k8s-certificate.json"
            report = Path(tmpdir) / "k8s-replay-report.json"

            verify_rc = main(
                [
                    "verify",
                    "kubernetes",
                    "--policies",
                    "examples/policies.yaml",
                    "--manifest",
                    "examples/k8s-manifest.yaml",
                    "--out",
                    str(cert),
                ]
            )
            self.assertEqual(verify_rc, 3)

            replay_rc = main(
                [
                    "replay",
                    "kubernetes",
                    "--policies",
                    "examples/policies.yaml",
                    "--manifest",
                    "examples/k8s-manifest.yaml",
                    "--expected-certificate",
                    str(cert),
                    "--out",
                    str(report),
                ]
            )
            self.assertEqual(replay_rc, 0)
            self.assertTrue(load_json(report)["valid"])


if __name__ == "__main__":
    unittest.main()
