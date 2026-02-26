from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .admission import run_admission_webhook
from .attestation import load_signing_key, sign_certificate, verify_certificate_offline
from .benchmark import run_benchmark
from .kubernetes import load_and_normalize_manifests
from .policy import compile_policy_file
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

    compile_parser = subparsers.add_parser("compile", help="compile policy YAML")
    compile_parser.add_argument("--policies", required=True, help="policy file in YAML format")
    compile_parser.add_argument("--out", required=True, help="output file for compiled policy JSON")
    compile_parser.add_argument("--trace", help="optional trace log output (jsonl)")

    verify_parser = subparsers.add_parser("verify", help="run deterministic policy verification")
    verify_subparsers = verify_parser.add_subparsers(dest="target", required=True)

    tf_parser = verify_subparsers.add_parser("terraform", help="verify Terraform plan JSON")
    tf_parser.add_argument("--policies", required=True, help="policy file in YAML format")
    tf_parser.add_argument("--plan", required=True, help="terraform show -json plan file")
    tf_parser.add_argument("--workspace", default="default", help="Terraform workspace name")
    tf_parser.add_argument("--out", required=True, help="certificate/evidence output JSON")
    tf_parser.add_argument("--trace", help="optional trace log output (jsonl)")
    tf_parser.add_argument("--signing-key-file", help="optional HMAC key file to sign certificate")
    tf_parser.add_argument("--signing-key-id", default="local", help="key identifier for signature")

    k8s_parser = verify_subparsers.add_parser("kubernetes", help="verify Kubernetes manifests")
    k8s_parser.add_argument("--policies", required=True, help="policy file in YAML format")
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
    admission_parser.add_argument("--policies", required=True, help="policy file in YAML format")
    admission_parser.add_argument("--host", default="0.0.0.0", help="bind host")
    admission_parser.add_argument("--port", type=int, default=8443, help="bind port")

    return parser


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
                    "policy_digest": compiled.digest,
                },
            )
            trace.flush()
            print(f"compiled {len(compiled.rules)} rules to {args.out}")
            return 0

        if args.command == "verify" and args.target == "terraform":
            compiled = compile_policy_file(Path(args.policies), trace)
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
            compiled = compile_policy_file(Path(args.policies), trace)
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
            run_admission_webhook(
                policy_file=Path(args.policies),
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


def _maybe_sign_certificate(
    certificate: dict[str, object],
    args: argparse.Namespace,
    trace: TraceLogger,
) -> dict[str, object]:
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
