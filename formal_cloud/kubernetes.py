from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import RuleViolation
from .yaml_compat import load_yaml_all

POD_SPEC_WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "ReplicaSet",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
}


def load_and_normalize_manifests(paths: list[Path]) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []

    for path in paths:
        docs = load_yaml_all(path)

        for index, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue

            metadata = doc.get("metadata") or {}
            kind = str(doc.get("kind", ""))
            name = str(metadata.get("name", f"unnamed-{index}"))
            namespace = str(metadata.get("namespace", "default"))

            resources.append(
                {
                    "source": str(path),
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "object": doc,
                }
            )

    resources.sort(key=lambda item: (item["kind"], item["namespace"], item["name"], item["source"]))
    return {"resources": resources}


def check_no_privileged_containers(resources: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []

    for resource in resources:
        pod_spec = _extract_pod_spec(resource.get("object") or {})
        if not pod_spec:
            continue

        for container_kind, container in _iter_containers(pod_spec):
            security_context = container.get("securityContext") or {}
            if security_context.get("privileged") is True:
                violations.append(
                    RuleViolation(
                        entity=_entity_id(resource, container),
                        message="Privileged containers are not allowed",
                        details={"container_kind": container_kind},
                    )
                )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_resources_limits(resources: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []

    for resource in resources:
        pod_spec = _extract_pod_spec(resource.get("object") or {})
        if not pod_spec:
            continue

        for container_kind, container in _iter_containers(pod_spec):
            limits = ((container.get("resources") or {}).get("limits") or {})
            if not limits.get("cpu") or not limits.get("memory"):
                violations.append(
                    RuleViolation(
                        entity=_entity_id(resource, container),
                        message="Container must set cpu and memory limits",
                        details={"container_kind": container_kind},
                    )
                )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_disallow_latest_tag(resources: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []

    for resource in resources:
        pod_spec = _extract_pod_spec(resource.get("object") or {})
        if not pod_spec:
            continue

        for container_kind, container in _iter_containers(pod_spec):
            image = container.get("image")
            if not isinstance(image, str) or not image:
                continue

            if image.endswith(":latest"):
                violations.append(
                    RuleViolation(
                        entity=_entity_id(resource, container),
                        message="Container image tag ':latest' is not allowed",
                        details={"image": image, "container_kind": container_kind},
                    )
                )
                continue

            if "@sha256:" not in image and _missing_tag(image):
                violations.append(
                    RuleViolation(
                        entity=_entity_id(resource, container),
                        message="Container image must use immutable digest or explicit tag",
                        details={"image": image, "container_kind": container_kind},
                    )
                )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_non_root(resources: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []

    for resource in resources:
        pod_spec = _extract_pod_spec(resource.get("object") or {})
        if not pod_spec:
            continue

        pod_security = pod_spec.get("securityContext") or {}
        pod_non_root = pod_security.get("runAsNonRoot")

        for container_kind, container in _iter_containers(pod_spec):
            container_security = container.get("securityContext") or {}
            container_non_root = container_security.get("runAsNonRoot")
            effective_non_root = container_non_root if container_non_root is not None else pod_non_root

            if effective_non_root is not True:
                violations.append(
                    RuleViolation(
                        entity=_entity_id(resource, container),
                        message="Container must enforce runAsNonRoot=true",
                        details={"container_kind": container_kind},
                    )
                )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def _extract_pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    kind = obj.get("kind")
    if kind not in POD_SPEC_WORKLOAD_KINDS:
        return None

    if kind == "Pod":
        return obj.get("spec") or {}

    spec = obj.get("spec") or {}
    if kind == "CronJob":
        return (
            ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
        ).get("spec") or {}

    return ((spec.get("template") or {}).get("spec") or {})


def _iter_containers(pod_spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    containers: list[tuple[str, dict[str, Any]]] = []

    for key in ("containers", "initContainers", "ephemeralContainers"):
        values = pod_spec.get(key) or []
        if not isinstance(values, list):
            continue
        for container in values:
            if isinstance(container, dict):
                containers.append((key, container))

    return containers


def _entity_id(resource: dict[str, Any], container: dict[str, Any]) -> str:
    container_name = container.get("name") or "unnamed"
    return (
        f"{resource.get('kind')}/{resource.get('namespace')}/{resource.get('name')}"
        f":{container_name}"
    )


def _missing_tag(image: str) -> bool:
    if "/" in image:
        tail = image.rsplit("/", maxsplit=1)[-1]
    else:
        tail = image
    return ":" not in tail
