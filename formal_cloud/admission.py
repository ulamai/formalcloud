from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .models import CompiledPolicySet
from .policy import compile_policy_file
from .verifier import verify_kubernetes


class AdmissionWebhookHandler(BaseHTTPRequestHandler):
    compiled_policy: CompiledPolicySet | None = None

    def do_GET(self) -> None:  # pragma: no cover - thin integration surface
        if self.path.rstrip("/") == "/healthz":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # pragma: no cover - thin integration surface
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)
            review = json.loads(raw_body.decode("utf-8"))
            response = evaluate_admission_review(
                review=review,
                compiled_policy=self.compiled_policy,
            )
            self._write_json(200, response)
        except Exception as exc:
            self._write_json(
                500,
                {
                    "error": str(exc),
                    "kind": "AdmissionReview",
                    "apiVersion": "admission.k8s.io/v1",
                },
            )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def evaluate_admission_review(
    review: dict[str, Any],
    compiled_policy: CompiledPolicySet | None,
) -> dict[str, Any]:
    if compiled_policy is None:
        raise ValueError("compiled policy is not configured")

    request = review.get("request") or {}
    uid = request.get("uid")
    obj = request.get("object") or request.get("oldObject")

    if not isinstance(obj, dict):
        return _build_review_response(
            api_version=review.get("apiVersion") or "admission.k8s.io/v1",
            uid=uid,
            allowed=True,
            message="No object payload; skipping policy checks",
            certificate_id=None,
        )

    normalized = {
        "resources": [
            {
                "source": "admission-review",
                "kind": str(obj.get("kind", "")),
                "name": str((obj.get("metadata") or {}).get("name", "unnamed")),
                "namespace": str((obj.get("metadata") or {}).get("namespace", "default")),
                "object": obj,
            }
        ]
    }

    certificate = verify_kubernetes(
        compiled=compiled_policy,
        normalized_manifests=normalized,
        trace=None,
    )

    allowed = certificate["decision"] == "accept"
    message = "accepted by formal-cloud"
    if not allowed:
        message = _build_rejection_message(certificate)

    return _build_review_response(
        api_version=review.get("apiVersion") or "admission.k8s.io/v1",
        uid=uid,
        allowed=allowed,
        message=message,
        certificate_id=certificate.get("certificate_id"),
    )


def run_admission_webhook(policy_file: Path, host: str, port: int) -> None:
    compiled = compile_policy_file(policy_file, trace=None)

    handler_class = type("ConfiguredAdmissionWebhookHandler", (AdmissionWebhookHandler,), {})
    handler_class.compiled_policy = compiled

    server = ThreadingHTTPServer((host, port), handler_class)
    print(
        "formal-cloud admission webhook listening "
        f"on http://{host}:{port} (configure TLS in front for production)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual shutdown path
        pass
    finally:
        server.server_close()


def _build_review_response(
    api_version: str,
    uid: str | None,
    allowed: bool,
    message: str,
    certificate_id: str | None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "uid": uid,
        "allowed": allowed,
        "status": {
            "message": message,
            "code": 200 if allowed else 403,
        },
        "auditAnnotations": {
            "formal-cloud/decision": "accept" if allowed else "reject",
        },
    }

    if certificate_id:
        response["auditAnnotations"]["formal-cloud/certificate-id"] = certificate_id

    return {
        "apiVersion": api_version,
        "kind": "AdmissionReview",
        "response": response,
    }


def _build_rejection_message(certificate: dict[str, Any]) -> str:
    reasons: list[str] = []
    for result in certificate.get("results") or []:
        if result.get("passed"):
            continue
        rule_id = result.get("id")
        for violation in result.get("violations") or []:
            reasons.append(f"{rule_id}: {violation.get('entity')}: {violation.get('message')}")
            if len(reasons) == 5:
                return "; ".join(reasons)

    if not reasons:
        return "rejected by formal-cloud policy"
    return "; ".join(reasons)
