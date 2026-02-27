from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from .attestation import SIGNATURE_SCHEME
from .models import CompiledPolicySet
from .policy import compile_policy_document, compile_policy_file
from .trace import TraceLogger
from .utils import canonical_dumps, load_json, sha256_obj, utc_now_iso

BUNDLE_SCHEMA_VERSION = "formal-cloud.bundle/v1"


def create_policy_bundle(
    policy_files: list[Path],
    bundle_id: str,
    bundle_version: str,
    key: bytes | None,
    key_id: str,
    trace: TraceLogger | None = None,
) -> dict[str, Any]:
    if not bundle_id.strip():
        raise ValueError("bundle_id must be a non-empty string")
    if not bundle_version.strip():
        raise ValueError("bundle_version must be a non-empty string")
    if not policy_files:
        raise ValueError("policy_files must be non-empty")

    entries: list[dict[str, Any]] = []
    seen_policy_ids: set[str] = set()

    for policy_file in policy_files:
        compiled = compile_policy_file(policy_file, trace=trace)
        if compiled.policy_set_id in seen_policy_ids:
            raise ValueError(
                f"duplicate policy_set_id '{compiled.policy_set_id}' in bundle inputs"
            )
        seen_policy_ids.add(compiled.policy_set_id)

        policy_document = _compiled_to_policy_document(compiled)
        entries.append(
            {
                "source": str(policy_file),
                "policy_set_id": compiled.policy_set_id,
                "policy_revision": compiled.policy_revision,
                "policy_digest": compiled.digest,
                "policy_document": policy_document,
            }
        )

    entries.sort(key=lambda item: (item["policy_set_id"], item["policy_revision"]))

    base = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle": {
            "id": bundle_id,
            "version": bundle_version,
            "created_at": utc_now_iso(),
            "policy_count": len(entries),
        },
        "policies": entries,
    }

    digest_seed = _bundle_digest_seed(base)
    bundle_digest = sha256_obj(digest_seed)

    bundle = dict(base)
    bundle["bundle_digest"] = bundle_digest

    if key is not None:
        bundle["signature"] = _sign_bundle(bundle, key=key, key_id=key_id)

    if trace:
        trace.event(
            "bundle.create",
            {
                "bundle_id": bundle_id,
                "bundle_version": bundle_version,
                "policy_count": len(entries),
                "bundle_digest": bundle_digest,
                "signed": key is not None,
            },
        )

    return bundle


def verify_policy_bundle(
    bundle: dict[str, Any],
    key: bytes | None,
    expected_version: str | None,
    require_signature: bool,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    schema = bundle.get("schema_version")
    checks.append(
        {
            "name": "bundle_schema",
            "ok": schema == BUNDLE_SCHEMA_VERSION,
            "message": f"expected schema {BUNDLE_SCHEMA_VERSION}",
            "actual": schema,
        }
    )

    bundle_meta = bundle.get("bundle") or {}
    bundle_id = bundle_meta.get("id")
    bundle_version = bundle_meta.get("version")

    checks.append(
        {
            "name": "bundle_id",
            "ok": isinstance(bundle_id, str) and bool(bundle_id.strip()),
            "message": "bundle.id must be non-empty",
            "actual": bundle_id,
        }
    )

    checks.append(
        {
            "name": "bundle_version",
            "ok": isinstance(bundle_version, str) and bool(bundle_version.strip()),
            "message": "bundle.version must be non-empty",
            "actual": bundle_version,
        }
    )

    if expected_version is not None:
        checks.append(
            {
                "name": "bundle_version_pin",
                "ok": bundle_version == expected_version,
                "message": "bundle version pin check",
                "actual": bundle_version,
                "expected": expected_version,
            }
        )

    try:
        expected_digest = sha256_obj(_bundle_digest_seed(bundle))
        actual_digest = bundle.get("bundle_digest")
        checks.append(
            {
                "name": "bundle_digest",
                "ok": isinstance(actual_digest, str)
                and hmac.compare_digest(actual_digest, expected_digest),
                "message": "bundle digest integrity",
                "actual": actual_digest,
                "expected": expected_digest,
            }
        )
    except Exception as exc:
        checks.append(
            {
                "name": "bundle_digest",
                "ok": False,
                "message": f"failed calculating bundle digest: {exc}",
            }
        )

    signature = bundle.get("signature")
    if signature is None:
        checks.append(
            {
                "name": "bundle_signature_present",
                "ok": not require_signature,
                "message": "bundle signature missing",
            }
        )
    else:
        checks.extend(_verify_bundle_signature(bundle=bundle, signature=signature, key=key))

    valid = all(item.get("ok") for item in checks)
    return {
        "valid": valid,
        "bundle_id": bundle_id,
        "bundle_version": bundle_version,
        "checks": checks,
    }


def load_compiled_policy_from_bundle(
    bundle_path: Path,
    policy_set_id: str | None,
    expected_bundle_version: str | None,
    key: bytes | None,
    require_signature: bool,
    trace: TraceLogger | None = None,
) -> CompiledPolicySet:
    bundle = load_json(bundle_path)
    report = verify_policy_bundle(
        bundle=bundle,
        key=key,
        expected_version=expected_bundle_version,
        require_signature=require_signature,
    )
    if not report["valid"]:
        failed = [item["name"] for item in report["checks"] if not item.get("ok")]
        raise ValueError(f"bundle verification failed for {bundle_path}: failed checks={failed}")

    entries = bundle.get("policies") or []
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"bundle {bundle_path} has no policies")

    if policy_set_id:
        matching = [entry for entry in entries if entry.get("policy_set_id") == policy_set_id]
        if not matching:
            raise ValueError(
                f"bundle {bundle_path} does not contain policy_set_id '{policy_set_id}'"
            )
        selected = matching[0]
    else:
        if len(entries) != 1:
            available = sorted(str(entry.get("policy_set_id")) for entry in entries)
            raise ValueError(
                "bundle contains multiple policies; provide --policy-set-id. "
                f"available={available}"
            )
        selected = entries[0]

    policy_document = selected.get("policy_document")
    if not isinstance(policy_document, dict):
        raise ValueError(f"bundle entry missing policy_document for policy {selected}")

    source = f"{bundle_path}#{selected.get('policy_set_id')}"
    compiled = compile_policy_document(policy_document, source=source, trace=trace)

    expected_policy_digest = selected.get("policy_digest")
    if not isinstance(expected_policy_digest, str):
        raise ValueError(f"bundle entry missing policy_digest for {source}")
    if not hmac.compare_digest(compiled.digest, expected_policy_digest):
        raise ValueError(f"bundle policy digest mismatch for {source}")

    if trace:
        trace.event(
            "bundle.load",
            {
                "bundle": str(bundle_path),
                "policy_set_id": compiled.policy_set_id,
                "policy_revision": compiled.policy_revision,
                "bundle_version": bundle.get("bundle", {}).get("version"),
            },
        )

    return compiled


def _bundle_digest_seed(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": bundle.get("schema_version"),
        "bundle": bundle.get("bundle"),
        "policies": bundle.get("policies"),
    }


def _compiled_to_policy_document(compiled: CompiledPolicySet) -> dict[str, Any]:
    policy_meta: dict[str, Any] = {
        "id": compiled.policy_set_id,
        "version": compiled.version,
        "revision": compiled.policy_revision,
        "compatibility": compiled.compatibility,
        "exception_policy": compiled.exception_policy,
    }
    if compiled.rollout:
        policy_meta["rollout"] = compiled.rollout

    return {
        "schema_version": compiled.schema_version,
        "policy": policy_meta,
        "rules": [rule.to_dict() for rule in compiled.rules],
        "exceptions": [exc.to_dict() for exc in compiled.exceptions],
    }


def _sign_bundle(bundle: dict[str, Any], key: bytes, key_id: str) -> dict[str, Any]:
    if not key_id.strip():
        raise ValueError("key_id must be non-empty when signing bundle")

    signable = dict(bundle)
    signable.pop("signature", None)

    payload = canonical_dumps(signable).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    signature_hex = hmac.new(key, payload, hashlib.sha256).hexdigest()

    bundle_meta = signable.get("bundle") or {}
    return {
        "scheme": SIGNATURE_SCHEME,
        "key_id": key_id,
        "signed_at": utc_now_iso(),
        "payload_hash": payload_hash,
        "signature": signature_hex,
        "bundle_id": bundle_meta.get("id"),
        "bundle_version": bundle_meta.get("version"),
    }


def _verify_bundle_signature(
    bundle: dict[str, Any], signature: Any, key: bytes | None
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    if not isinstance(signature, dict):
        return [
            {
                "name": "bundle_signature_format",
                "ok": False,
                "message": "bundle signature must be an object",
            }
        ]

    scheme = signature.get("scheme")
    checks.append(
        {
            "name": "bundle_signature_scheme",
            "ok": scheme == SIGNATURE_SCHEME,
            "message": f"expected signature scheme {SIGNATURE_SCHEME}",
            "actual": scheme,
        }
    )

    signable = dict(bundle)
    signable.pop("signature", None)
    payload = canonical_dumps(signable).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    declared_payload_hash = signature.get("payload_hash")

    checks.append(
        {
            "name": "bundle_signature_payload_hash",
            "ok": isinstance(declared_payload_hash, str)
            and hmac.compare_digest(declared_payload_hash, payload_hash),
            "message": "bundle signature payload hash matches",
            "actual": declared_payload_hash,
            "expected": payload_hash,
        }
    )

    bundle_meta = bundle.get("bundle") or {}
    checks.append(
        {
            "name": "bundle_signature_binding",
            "ok": signature.get("bundle_id") == bundle_meta.get("id")
            and signature.get("bundle_version") == bundle_meta.get("version"),
            "message": "bundle signature binding",
            "actual": {
                "bundle_id": signature.get("bundle_id"),
                "bundle_version": signature.get("bundle_version"),
            },
            "expected": {
                "bundle_id": bundle_meta.get("id"),
                "bundle_version": bundle_meta.get("version"),
            },
        }
    )

    if key is None:
        checks.append(
            {
                "name": "bundle_signature_key",
                "ok": False,
                "message": "no key provided for signed bundle verification",
            }
        )
        return checks

    expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    actual_signature = signature.get("signature")
    checks.append(
        {
            "name": "bundle_signature_value",
            "ok": isinstance(actual_signature, str)
            and hmac.compare_digest(actual_signature, expected_signature),
            "message": "bundle signature value",
            "actual": actual_signature,
            "expected": expected_signature,
        }
    )

    return checks
