import unittest
from pathlib import Path

from formal_cloud.admission import evaluate_admission_review
from formal_cloud.policy import compile_policy_file


class AdmissionTests(unittest.TestCase):
    def test_rejects_insecure_object(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc-123",
                "object": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad", "namespace": "prod"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "bad"}},
                        "template": {
                            "metadata": {"labels": {"app": "bad"}},
                            "spec": {
                                "containers": [
                                    {
                                        "name": "web",
                                        "image": "nginx:latest",
                                        "securityContext": {"privileged": True},
                                    }
                                ]
                            },
                        },
                    },
                },
            },
        }

        response = evaluate_admission_review(review, compiled)
        self.assertFalse(response["response"]["allowed"])
        self.assertIn("formal-cloud/certificate-id", response["response"]["auditAnnotations"])

    def test_accepts_secure_object(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "def-456",
                "object": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good", "namespace": "prod"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "good"}},
                        "template": {
                            "metadata": {"labels": {"app": "good"}},
                            "spec": {
                                "securityContext": {"runAsNonRoot": True},
                                "containers": [
                                    {
                                        "name": "web",
                                        "image": "ghcr.io/example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                        "securityContext": {
                                            "privileged": False,
                                            "runAsNonRoot": True,
                                        },
                                        "resources": {
                                            "limits": {"cpu": "250m", "memory": "256Mi"}
                                        },
                                    }
                                ],
                            },
                        },
                    },
                },
            },
        }

        response = evaluate_admission_review(review, compiled)
        self.assertTrue(response["response"]["allowed"])


if __name__ == "__main__":
    unittest.main()
