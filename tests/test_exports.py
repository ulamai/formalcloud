import tempfile
import unittest
from pathlib import Path

from formal_cloud.evidence_pack import create_evidence_pack
from formal_cloud.github_checks import certificate_to_github_checks
from formal_cloud.intoto import certificate_to_intoto_statement
from formal_cloud.junit import certificate_to_junit_xml
from formal_cloud.policy import compile_policy_file
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json, write_json
from formal_cloud.verifier import verify_terraform


class ExportTests(unittest.TestCase):
    def test_exports_from_certificate(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))
        certificate = verify_terraform(compiled, normalized_plan=plan, workspace="prod")

        junit = certificate_to_junit_xml(certificate)
        self.assertIn("<testsuite", junit)
        self.assertIn("<failure", junit)

        checks = certificate_to_github_checks(certificate)
        self.assertEqual(checks["name"], "FormalCloud")
        self.assertEqual(checks["conclusion"], "failure")
        self.assertGreater(len(checks["output"]["annotations"]), 0)

        statement = certificate_to_intoto_statement(certificate)
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(
            statement["predicate"]["decision"]["certificate_id"],
            certificate["certificate_id"],
        )

    def test_evidence_pack_creation(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-controls.yaml"))
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))
        certificate = verify_terraform(compiled, normalized_plan=plan, workspace="prod")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cert_path = tmp / "certificate.json"
            trace_path = tmp / "trace.jsonl"
            extra_path = tmp / "extra.txt"

            write_json(cert_path, certificate)
            trace_path.write_text('{"event":"trace"}\n', encoding="utf-8")
            extra_path.write_text("extra", encoding="utf-8")

            manifest = create_evidence_pack(
                certificate_path=cert_path,
                out_dir=tmp / "pack",
                trace_path=trace_path,
                extra_files=[extra_path],
            )
            self.assertEqual(manifest["schema_version"], "formal-cloud.evidence-pack/v1")
            self.assertEqual(manifest["certificate_id"], certificate["certificate_id"])
            self.assertGreaterEqual(len(manifest["files"]), 3)
            self.assertGreaterEqual(manifest["controls"]["mapped_controls"], 1)
            self.assertGreaterEqual(len(manifest["controls"]["failing_control_ids"]), 1)


if __name__ == "__main__":
    unittest.main()
