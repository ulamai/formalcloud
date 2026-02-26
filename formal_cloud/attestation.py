from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path
from typing import Any

from .utils import canonical_dumps, utc_now_iso

SIGNATURE_SCHEME = "hmac-sha256"


def load_signing_key(path: Path) -> bytes:
    raw_key = path.read_text(encoding="utf-8").strip()
    if not raw_key:
        raise ValueError(f"signing key file {path} is empty")
    return raw_key.encode("utf-8")


def sign_certificate(certificate: dict[str, Any], key: bytes, key_id: str) -> dict[str, Any]:
    if not key_id.strip():
        raise ValueError("key_id must be a non-empty string")

    signable = _without_signature(certificate)
    payload = canonical_dumps(signable).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    signature_hex = hmac.new(key, payload, hashlib.sha256).hexdigest()

    signed = copy.deepcopy(signable)
    signed["signature"] = {
        "scheme": SIGNATURE_SCHEME,
        "key_id": key_id,
        "signed_at": utc_now_iso(),
        "payload_hash": payload_hash,
        "signature": signature_hex,
        "certificate_id": signed.get("certificate_id"),
    }
    return signed


def verify_certificate_offline(
    certificate: dict[str, Any],
    key: bytes | None,
    require_signature: bool = True,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    cert_id_check = _verify_certificate_id(certificate)
    checks.append(cert_id_check)

    signature_obj = certificate.get("signature")
    if signature_obj is None:
        checks.append(
            {
                "name": "signature_present",
                "ok": not require_signature,
                "message": "signature is missing",
            }
        )
    else:
        checks.extend(_verify_signature(certificate, signature_obj, key))

    valid = all(check.get("ok") for check in checks)
    return {
        "valid": valid,
        "certificate_id": certificate.get("certificate_id"),
        "checks": checks,
    }


def _verify_certificate_id(certificate: dict[str, Any]) -> dict[str, Any]:
    from .verifier import compute_certificate_id_from_certificate

    try:
        expected = compute_certificate_id_from_certificate(certificate)
    except Exception as exc:
        return {
            "name": "certificate_id_integrity",
            "ok": False,
            "message": f"unable to recompute certificate_id: {exc}",
        }

    actual = certificate.get("certificate_id")
    ok = isinstance(actual, str) and hmac.compare_digest(actual, expected)
    return {
        "name": "certificate_id_integrity",
        "ok": ok,
        "message": "certificate_id matches deterministic recomputation"
        if ok
        else "certificate_id mismatch",
        "expected": expected,
        "actual": actual,
    }


def _verify_signature(
    certificate: dict[str, Any], signature_obj: Any, key: bytes | None
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    if not isinstance(signature_obj, dict):
        return [
            {
                "name": "signature_format",
                "ok": False,
                "message": "signature must be an object",
            }
        ]

    scheme = signature_obj.get("scheme")
    checks.append(
        {
            "name": "signature_scheme",
            "ok": scheme == SIGNATURE_SCHEME,
            "message": f"expected signature scheme {SIGNATURE_SCHEME}",
            "actual": scheme,
        }
    )

    cert_id = certificate.get("certificate_id")
    bound_cert_id = signature_obj.get("certificate_id")
    checks.append(
        {
            "name": "signature_certificate_binding",
            "ok": isinstance(bound_cert_id, str) and cert_id == bound_cert_id,
            "message": "signature is bound to certificate_id",
            "actual": bound_cert_id,
            "expected": cert_id,
        }
    )

    signable = _without_signature(certificate)
    payload = canonical_dumps(signable).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    declared_payload_hash = signature_obj.get("payload_hash")

    checks.append(
        {
            "name": "signature_payload_hash",
            "ok": isinstance(declared_payload_hash, str)
            and hmac.compare_digest(declared_payload_hash, payload_hash),
            "message": "signature payload hash matches certificate body",
            "actual": declared_payload_hash,
            "expected": payload_hash,
        }
    )

    if key is None:
        checks.append(
            {
                "name": "signature_key",
                "ok": False,
                "message": "no signing key provided for signature verification",
            }
        )
        return checks

    expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    actual_signature = signature_obj.get("signature")
    checks.append(
        {
            "name": "signature_value",
            "ok": isinstance(actual_signature, str)
            and hmac.compare_digest(actual_signature, expected_signature),
            "message": "signature value matches HMAC-SHA256",
            "actual": actual_signature,
            "expected": expected_signature,
        }
    )

    return checks


def _without_signature(certificate: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(certificate)
    value.pop("signature", None)
    return value
