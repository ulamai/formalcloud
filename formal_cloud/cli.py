from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .admission import run_admission_webhook_compiled
from .attestation import load_signing_key, sign_certificate, verify_certificate_offline
from .benchmark import run_benchmark
from .bundle import create_policy_bundle, load_compiled_policy_from_bundle, verify_policy_bundle
from .kubernetes import load_and_normalize_manifests
from .policy import compile_policy_file
from .sarif import certificate_to_sarif
from .terraform import normalize_plan
from .trace import TraceLogger
from .utils import load_json, write_json
from .verifier import verify_kubernetes, verify_terraform


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="formal-cloud",
        description="Formal checks for cloud infrastructure and policy-as-code compliance",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compile_parser = subparsers.add_parser("compile", help="compile policy source")
    compile_parser.add_argument(
        "--policies",
        required=True,
        help="policy file in YAML/JSON/Rego/Kyverno format",
    )
    compile_parser.add_argument("--out", required=True, help="output file for compiled policy JSON")
    compile_parser.add_argument("--trace", help="optional trace log output (jsonl)")

    verify_parser = subparsers.add_parser("verify", help="run deterministic policy verification")
    verify_subparsers = verify_parser.add_subparsers(dest="target", required=True)

    tf_parser = verify_subparsers.add_parser("terraform", help="verify Terraform plan JSON")
    _add_policy_source_args(tf_parser)
    tf_parser.add_argument("--plan", required=True, help="terraform show -json plan file")
    tf_parser.add_argument("--workspace", default="default", help="Terraform workspace name")
    tf_parser.add_argument("--out", required=True, help="certificate/evidence output JSON")
    tf_parser.add_argument("--trace", help="optional trace log output (jsonl)")
    tf_parser.add_argument("--signing-key-file", help="optional HMAC key file to sign certificate")
    tf_parser.add_argument("--signing-key-id", default="local", help="key identifier for signature")

    k8s_parser = verify_subparsers.add_parser("kubernetes", help="verify Kubernetes manifests")
    _add_policy_source_args(k8s_parser)
    k8s_parser.add_argument(
        "--manifest",
        action="append",
        required=True,
        help="path to YAML manifest (repeat flag for multiple files)",
    )
    k8s_parser.add_argument("--out", required=True, help="certificate/evidence output JSON")
    k8s_parser.add_argument("--trace", help="optional trace log output (jsonl)")
    k8s_parser.add_argument("--signing-key-file", help="optional HMAC key file to sign certificate")
    k8s_parser.add_argument("--signing-key-id", default="local", help="key identifier for signature")

    attest_parser = subparsers.add_parser(
        "attest", help="sign or verify certificate artifacts offline"
    )
    attest_subparsers = attest_parser.add_subparsers(dest="attest_command", required=True)

    attest_sign = attest_subparsers.add_parser("sign", help="sign a certificate JSON artifact")
    attest_sign.add_argument("--certificate", required=True, help="input certificate JSON")
    attest_sign.add_argument("--key-file", required=True, help="HMAC key file")
    attest_sign.add_argument("--key-id", default="local", help="signature key identifier")
    attest_sign.add_argument("--out", required=True, help="signed certificate output JSON")

    attest_verify = attest_subparsers.add_parser(
        "verify", help="verify certificate integrity and signature"
    )
    attest_verify.add_argument("--certificate", required=True, help="certificate JSON")
    attest_verify.add_argument("--key-file", help="HMAC key file (required for signed certs)")
    attest_verify.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="allow unsigned certificates (still validates certificate_id integrity)",
    )
    attest_verify.add_argument("--out", help="optional verification report output JSON")

    bundle_parser = subparsers.add_parser(
        "bundle", help="create and verify signed policy bundles"
    )
    bundle_subparsers = bundle_parser.add_subparsers(dest="bundle_command", required=True)

    bundle_create = bundle_subparsers.add_parser("create", help="create policy bundle")
    bundle_create.add_argument("--bundle-id", required=True, help="bundle identifier")
    bundle_create.add_argument("--bundle-version", required=True, help="bundle version")
    bundle_create.add_argument(
        "--policy-file",
        action="append",
        required=True,
        help="policy source file path (repeat for multiple files)",
    )
    bundle_create.add_argument("--out", required=True, help="bundle output JSON")
    bundle_create.add_argument("--trace", help="optional trace log output (jsonl)")
    bundle_create.add_argument("--signing-key-file", help="optional HMAC key file")
    bundle_create.add_argument("--signing-key-id", default="local", help="signature key id")

    bundle_verify = bundle_subparsers.add_parser("verify", help="verify policy bundle")
    bundle_verify.add_argument("--bundle", required=True, help="bundle JSON file")
    bundle_verify.add_argument("--expected-version", help="expected bundle version")
    bundle_verify.add_argument("--key-file", help="HMAC key file")
    bundle_verify.add_argument(
        "--require-signature",
        action="store_true",
        help="require verified signature",
    )
    bundle_verify.add_argument("--out", help="optional verification report output JSON")

    export_parser = subparsers.add_parser("export", help="export evidence formats")
    export_subparsers = export_parser.add_subparsers(dest="export_target", required=True)

    export_sarif = export_subparsers.add_parser("sarif", help="export SARIF from certificate")
    export_sarif.add_argument("--certificate", required=True, help="certificate JSON")
    export_sarif.add_argument("--out", required=True, help="output SARIF JSON")
    export_sarif.add_argument("--tool-name", default="FormalCloud", help="SARIF tool name")
    export_sarif.add_argument(
        "--include-waived",
        action="store_true",
        help="include waived violations as suppressed SARIF results",
    )

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="run deterministic reproducibility benchmark corpus"
    )
    benchmark_subparsers = benchmark_parser.add_subparsers(dest="benchmark_command", required=True)
    benchmark_run = benchmark_subparsers.add_parser("run", help="run benchmark corpus")
    benchmark_run.add_argument("--cases", required=True, help="benchmark cases YAML/JSON")
    benchmark_run.add_argument(
        "--iterations", type=int, default=5, help="iterations per case (default: 5)"
    )
    benchmark_run.add_argument("--out", required=True, help="benchmark report output JSON")

    admission_parser = subparsers.add_parser(
        "admission-webhook", help="run Kubernetes validating admission webhook"
    )
    _add_policy_source_args(admission_parser)
    admission_parser.add_argument("--host", default="0.0.0.0", help="bind host")
    admission_parser.add_argument("--port", type=int, default=8443, help="bind port")

    return parser


def _add_policy_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policies", help="policy source file")
    parser.add_argument("--bundle", help="policy bundle JSON")
    parser.add_argument("--policy-set-id", help="policy_set_id to select from bundle")
    parser.add_argument("--bundle-version", help="expected bundle version (pin)")
    parser.add_argument("--bundle-key-file", help="bundle verification key file")
    parser.add_argument(
        "--bundle-require-signature",
        action="store_true",
        help="require bundle signature verification",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    trace_path = Path(args.trace) if getattr(args, "trace", None) else None
    trace = TraceLogger(trace_path)

    try:
        if args.command == "compile":
            compiled = compile_policy_file(Path(args.policies), trace)
            write_json(Path(args.out), compiled.to_dict())
            trace.event(
                "compile.finish",
                {
                    "output": str(args.out),
                    "rule_count": len(compiled.rules),
                    "exception_count": len(compiled.exceptions),
                    "policy_digest": compiled.digest,
                },
            )
            trace.flush()
            print(f"compiled {len(compiled.rules)} rules to {args.out}")
            return 0

        if args.command == "verify" and args.target == "terraform":
            compiled = _load_compiled_policy(args, trace)
            plan = load_json(Path(args.plan))
            normalized_plan = normalize_plan(plan)
            certificate = verify_terraform(
                compiled=compiled,
                normalized_plan=normalized_plan,
                workspace=args.workspace,
                trace=trace,
            )
            if trace_path:
                certificate["trace_log"] = str(trace_path)
            certificate = _maybe_sign_certificate(certificate, args, trace)
            write_json(Path(args.out), certificate)
            trace.event(
                "verify.finish",
                {
                    "target": "terraform",
                    "decision": certificate["decision"],
                    "certificate_id": certificate["certificate_id"],
                    "signed": "signature" in certificate,
                    "output": str(args.out),
                },
            )
            trace.flush()
            print(
                f"terraform decision={certificate['decision']} "
                f"violations={certificate['summary']['total_violations']} "
                f"certificate={certificate['certificate_id']}"
            )
            return 0 if certificate["decision"] == "accept" else 3

        if args.command == "verify" and args.target == "kubernetes":
            compiled = _load_compiled_policy(args, trace)
            manifests = load_and_normalize_manifests([Path(path) for path in args.manifest])
            certificate = verify_kubernetes(
                compiled=compiled,
                normalized_manifests=manifests,
                trace=trace,
            )
            if trace_path:
                certificate["trace_log"] = str(trace_path)
            certificate = _maybe_sign_certificate(certificate, args, trace)
            write_json(Path(args.out), certificate)
            trace.event(
                "verify.finish",
                {
                    "target": "kubernetes",
                    "decision": certificate["decision"],
                    "certificate_id": certificate["certificate_id"],
                    "signed": "signature" in certificate,
                    "output": str(args.out),
                },
            )
            trace.flush()
            print(
                f"kubernetes decision={certificate['decision']} "
                f"violations={certificate['summary']['total_violations']} "
                f"certificate={certificate['certificate_id']}"
            )
            return 0 if certificate["decision"] == "accept" else 3

        if args.command == "attest" and args.attest_command == "sign":
            certificate = load_json(Path(args.certificate))
            key = load_signing_key(Path(args.key_file))
            signed = sign_certificate(certificate, key=key, key_id=args.key_id)
            write_json(Path(args.out), signed)
            print(f"signed certificate={signed.get('certificate_id')} key_id={args.key_id}")
            return 0

        if args.command == "attest" and args.attest_command == "verify":
            certificate = load_json(Path(args.certificate))
            key = load_signing_key(Path(args.key_file)) if args.key_file else None
            report = verify_certificate_offline(
                certificate=certificate,
                key=key,
                require_signature=not args.allow_unsigned,
            )
            if args.out:
                write_json(Path(args.out), report)
            print(
                f"certificate valid={report['valid']} "
                f"checks={len(report['checks'])}"
            )
            return 0 if report["valid"] else 4

        if args.command == "bundle" and args.bundle_command == "create":
            key = load_signing_key(Path(args.signing_key_file)) if args.signing_key_file else None
            bundle = create_policy_bundle(
                policy_files=[Path(path) for path in args.policy_file],
                bundle_id=args.bundle_id,
                bundle_version=args.bundle_version,
                key=key,
                key_id=args.signing_key_id,
                trace=trace,
            )
            write_json(Path(args.out), bundle)
            trace.flush()
            print(
                f"bundle created id={bundle['bundle']['id']} "
                f"version={bundle['bundle']['version']} policies={bundle['bundle']['policy_count']}"
            )
            return 0

        if args.command == "bundle" and args.bundle_command == "verify":
            key = load_signing_key(Path(args.key_file)) if args.key_file else None
            bundle = load_json(Path(args.bundle))
            report = verify_policy_bundle(
                bundle=bundle,
                key=key,
                expected_version=args.expected_version,
                require_signature=args.require_signature,
            )
            if args.out:
                write_json(Path(args.out), report)
            print(
                f"bundle valid={report['valid']} "
                f"id={report.get('bundle_id')} version={report.get('bundle_version')}"
            )
            return 0 if report["valid"] else 6

        if args.command == "export" and args.export_target == "sarif":
            certificate = load_json(Path(args.certificate))
            sarif = certificate_to_sarif(
                certificate=certificate,
                tool_name=args.tool_name,
                include_waived=args.include_waived,
            )
            write_json(Path(args.out), sarif)
            result_count = len((sarif.get("runs") or [{}])[0].get("results") or [])
            print(f"sarif exported results={result_count} output={args.out}")
            return 0

        if args.command == "benchmark" and args.benchmark_command == "run":
            report = run_benchmark(Path(args.cases), iterations=args.iterations)
            write_json(Path(args.out), report)
            summary = report["summary"]
            print(
                f"benchmark pass={summary['pass']} "
                f"cases={summary['total_cases']} failed={summary['failed_cases']}"
            )
            return 0 if summary["pass"] else 5

        if args.command == "admission-webhook":
            compiled = _load_compiled_policy(args, trace)
            run_admission_webhook_compiled(
                compiled_policy=compiled,
                host=args.host,
                port=args.port,
            )
            return 0

        parser.error("unknown command")
        return 1
    except Exception as exc:  # pragma: no cover - defensive CLI error boundary
        trace.event("error", {"message": str(exc)})
        trace.flush()
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _load_compiled_policy(args: argparse.Namespace, trace: TraceLogger):
    policies = getattr(args, "policies", None)
    bundle = getattr(args, "bundle", None)

    if bool(policies) == bool(bundle):
        raise ValueError("provide exactly one of --policies or --bundle")

    if policies:
        return compile_policy_file(Path(policies), trace)

    bundle_key_file = getattr(args, "bundle_key_file", None)
    key = load_signing_key(Path(bundle_key_file)) if bundle_key_file else None
    return load_compiled_policy_from_bundle(
        bundle_path=Path(bundle),
        policy_set_id=getattr(args, "policy_set_id", None),
        expected_bundle_version=getattr(args, "bundle_version", None),
        key=key,
        require_signature=bool(getattr(args, "bundle_require_signature", False)),
        trace=trace,
    )


def _maybe_sign_certificate(
    certificate: dict[str, Any],
    args: argparse.Namespace,
    trace: TraceLogger,
) -> dict[str, Any]:
    key_file = getattr(args, "signing_key_file", None)
    if not key_file:
        return certificate

    key = load_signing_key(Path(key_file))
    key_id = str(getattr(args, "signing_key_id", "local"))
    signed = sign_certificate(certificate, key=key, key_id=key_id)
    trace.event(
        "certificate.sign",
        {
            "key_id": key_id,
            "scheme": signed.get("signature", {}).get("scheme"),
        },
    )
    return signed


if __name__ == "__main__":
    raise SystemExit(main())
