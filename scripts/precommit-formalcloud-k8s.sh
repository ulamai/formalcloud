#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  exit 0
fi

changed_file_list="$(mktemp)"
output_file="$(mktemp)"
trap 'rm -f "$changed_file_list" "$output_file"' EXIT

for file in "$@"; do
  printf '%s\n' "$file" >> "$changed_file_list"
done

if command -v formal-cloud >/dev/null 2>&1; then
  fc_cmd=(formal-cloud)
else
  fc_cmd=(python3 -m formal_cloud.cli)
fi

"${fc_cmd[@]}" verify kubernetes \
  --policies "${FORMALCLOUD_POLICIES:-examples/policies.yaml}" \
  --manifest-dir "${FORMALCLOUD_MANIFEST_DIR:-.}" \
  --changed-files-file "$changed_file_list" \
  --out "$output_file" \
  >/dev/null
