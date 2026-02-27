import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_document, compile_policy_file
from formal_cloud.terraform import (
    check_disallow_rdp_from_internet,
    check_disallow_ssh_from_internet,
    check_disallow_wide_cidr_egress,
    check_disallow_wide_cidr_ingress,
    check_require_imdsv2,
    check_require_kms_key_rotation,
    check_require_log_retention_min_days,
    check_require_rds_backup_retention,
    check_require_rds_deletion_protection,
    check_require_rds_multi_az,
    check_require_s3_bucket_logging,
    check_require_s3_versioning,
)
from formal_cloud.verifier import verify_terraform


def _resource(
    address: str,
    resource_type: str,
    after: dict,
    actions: list[str] | None = None,
) -> dict:
    return {
        "address": address,
        "type": resource_type,
        "actions": actions or ["create"],
        "after": after,
    }


class TerraformPilotCheckTests(unittest.TestCase):
    def test_compile_pilot_policy_profile(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-pilot-terraform.yaml"))
        self.assertEqual(compiled.policy_set_id, "org.formalcloud.pilot.terraform")
        self.assertEqual(len(compiled.rules), 15)
        self.assertTrue(all(rule.target == "terraform" for rule in compiled.rules))

    def test_security_group_wide_cidr_checks(self) -> None:
        insecure = [
            _resource(
                "aws_security_group.open",
                "aws_security_group",
                {
                    "ingress": [
                        {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}
                    ],
                    "egress": [
                        {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                    ],
                },
            )
        ]
        secure = [
            _resource(
                "aws_security_group.restricted",
                "aws_security_group",
                {
                    "ingress": [
                        {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_blocks": ["10.0.0.0/16"]}
                    ],
                    "egress": [
                        {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/16"]}
                    ],
                },
            )
        ]

        self.assertEqual(len(check_disallow_wide_cidr_ingress(insecure)), 1)
        self.assertEqual(len(check_disallow_wide_cidr_egress(insecure)), 1)
        self.assertEqual(len(check_disallow_wide_cidr_ingress(secure)), 0)
        self.assertEqual(len(check_disallow_wide_cidr_egress(secure)), 0)

    def test_ssh_and_rdp_exposure_checks(self) -> None:
        insecure = [
            _resource(
                "aws_security_group_rule.ssh",
                "aws_security_group_rule",
                {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ),
            _resource(
                "aws_security_group_rule.rdp",
                "aws_security_group_rule",
                {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ),
        ]
        secure = [
            _resource(
                "aws_security_group_rule.internal",
                "aws_security_group_rule",
                {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["10.0.0.0/16"],
                },
            )
        ]

        self.assertEqual(len(check_disallow_ssh_from_internet(insecure)), 1)
        self.assertEqual(len(check_disallow_rdp_from_internet(insecure)), 1)
        self.assertEqual(len(check_disallow_ssh_from_internet(secure)), 0)
        self.assertEqual(len(check_disallow_rdp_from_internet(secure)), 0)

    def test_s3_versioning_and_logging_checks(self) -> None:
        insecure = [
            _resource(
                "aws_s3_bucket.logs",
                "aws_s3_bucket",
                {"bucket": "logs-bucket"},
            )
        ]
        secure = [
            _resource(
                "aws_s3_bucket.logs",
                "aws_s3_bucket",
                {"bucket": "logs-bucket"},
            ),
            _resource(
                "aws_s3_bucket_versioning.logs",
                "aws_s3_bucket_versioning",
                {
                    "bucket": "logs-bucket",
                    "versioning_configuration": {"status": "Enabled"},
                },
            ),
            _resource(
                "aws_s3_bucket_logging.logs",
                "aws_s3_bucket_logging",
                {"bucket": "logs-bucket", "target_bucket": "audit-logs"},
            ),
        ]

        self.assertEqual(len(check_require_s3_versioning(insecure)), 1)
        self.assertEqual(len(check_require_s3_bucket_logging(insecure)), 1)
        self.assertEqual(len(check_require_s3_versioning(secure)), 0)
        self.assertEqual(len(check_require_s3_bucket_logging(secure)), 0)

    def test_rds_backup_multi_az_and_deletion_protection_checks(self) -> None:
        insecure = [
            _resource(
                "aws_db_instance.main",
                "aws_db_instance",
                {
                    "backup_retention_period": 1,
                    "multi_az": False,
                    "deletion_protection": False,
                },
            )
        ]
        secure = [
            _resource(
                "aws_db_instance.main",
                "aws_db_instance",
                {
                    "backup_retention_period": 14,
                    "multi_az": True,
                    "deletion_protection": True,
                },
            )
        ]

        self.assertEqual(
            len(check_require_rds_backup_retention(insecure, {"min_days": 7})),
            1,
        )
        self.assertEqual(len(check_require_rds_multi_az(insecure)), 1)
        self.assertEqual(len(check_require_rds_deletion_protection(insecure)), 1)

        self.assertEqual(
            len(check_require_rds_backup_retention(secure, {"min_days": 7})),
            0,
        )
        self.assertEqual(len(check_require_rds_multi_az(secure)), 0)
        self.assertEqual(len(check_require_rds_deletion_protection(secure)), 0)

    def test_imdsv2_kms_rotation_and_log_retention_checks(self) -> None:
        insecure = [
            _resource(
                "aws_instance.web",
                "aws_instance",
                {"metadata_options": {"http_tokens": "optional"}},
            ),
            _resource(
                "aws_kms_key.main",
                "aws_kms_key",
                {"enable_key_rotation": False},
            ),
            _resource(
                "aws_cloudwatch_log_group.app",
                "aws_cloudwatch_log_group",
                {"retention_in_days": 7},
            ),
        ]
        secure = [
            _resource(
                "aws_instance.web",
                "aws_instance",
                {"metadata_options": {"http_tokens": "required"}},
            ),
            _resource(
                "aws_kms_key.main",
                "aws_kms_key",
                {"enable_key_rotation": True},
            ),
            _resource(
                "aws_cloudwatch_log_group.app",
                "aws_cloudwatch_log_group",
                {"retention_in_days": 90},
            ),
        ]

        self.assertEqual(len(check_require_imdsv2(insecure)), 1)
        self.assertEqual(len(check_require_kms_key_rotation(insecure)), 1)
        self.assertEqual(
            len(check_require_log_retention_min_days(insecure, {"min_days": 30})),
            1,
        )

        self.assertEqual(len(check_require_imdsv2(secure)), 0)
        self.assertEqual(len(check_require_kms_key_rotation(secure)), 0)
        self.assertEqual(
            len(check_require_log_retention_min_days(secure, {"min_days": 30})),
            0,
        )

    def test_verifier_dispatch_for_new_check(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.imdsv2.dispatch",
                "version": 1,
                "revision": "1",
                "compatibility": {},
            },
            "rules": [
                {
                    "id": "TFX001",
                    "title": "Require IMDSv2",
                    "target": "terraform",
                    "check": "require_imdsv2",
                    "severity": "high",
                }
            ],
        }
        compiled = compile_policy_document(policy_doc, source="<test>")
        cert = verify_terraform(
            compiled=compiled,
            normalized_plan={
                "resource_changes": [
                    _resource(
                        "aws_instance.web",
                        "aws_instance",
                        {"metadata_options": {"http_tokens": "optional"}},
                    )
                ]
            },
            workspace="prod",
        )
        self.assertEqual(cert["decision"], "reject")
        self.assertEqual(cert["summary"]["total_violations"], 1)


if __name__ == "__main__":
    unittest.main()
