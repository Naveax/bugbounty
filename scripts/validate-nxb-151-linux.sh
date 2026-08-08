#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
workspace=""
nonempty_workspace=""
broken_workspace=""
results_file=""

cleanup() {
  [[ -n "$workspace" ]] && rm -rf -- "$workspace"
  [[ -n "$nonempty_workspace" ]] && rm -rf -- "$nonempty_workspace"
  [[ -n "$broken_workspace" ]] && rm -rf -- "$broken_workspace"
  [[ -n "$results_file" ]] && rm -f -- "$results_file"
}
trap cleanup EXIT

record_gate() {
  local name="$1"
  shift
  local started finished exit_code
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  "$@"
  exit_code=$?
  set -e
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$exit_code" "$started" "$finished" "$*" >> "$results_file"
  if [[ $exit_code -ne 0 ]]; then
    printf 'gate %s failed with exit code %s\n' "$name" "$exit_code" >&2
    exit "$exit_code"
  fi
}

record_expected_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  local started finished exit_code
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  "$@" >/dev/null 2>&1
  exit_code=$?
  set -e
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$exit_code" "$started" "$finished" "$*" >> "$results_file"
  if [[ $exit_code -ne $expected ]]; then
    printf 'gate %s returned %s; expected %s\n' "$name" "$exit_code" "$expected" >&2
    exit 1
  fi
}

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'invalid Git HEAD' >&2; exit 1; }
[[ -z "$(git status --porcelain=v1)" ]] || { echo 'working tree must be clean' >&2; exit 1; }

rustc_version="$(rustc --version)"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] || {
  printf 'expected rustc 1.97.1, found %s\n' "$rustc_version" >&2
  exit 1
}
cargo_version="$(cargo --version)"
rustfmt_version="$(rustfmt --version)"
clippy_version="$(cargo clippy --version)"

results_file="$(mktemp)"
record_gate cargo_fmt cargo fmt --all -- --check
record_gate cargo_check cargo check -p nxb-core --all-targets --all-features --locked
record_gate cargo_clippy cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
record_gate cargo_test cargo test -p nxb-core --all-features --locked -- --test-threads=1
record_gate cargo_build_nxb cargo build -p nxb-core --bin nxb --all-features --locked

binary="$repo_root/target/debug/nxb"
[[ -x "$binary" ]] || { printf 'nxb binary is missing: %s\n' "$binary" >&2; exit 1; }

workspace="$(mktemp -d -t nxb-151-XXXXXX)"
rmdir -- "$workspace"
nonempty_workspace="$(mktemp -d -t nxb-151-nonempty-XXXXXX)"
broken_workspace="$(mktemp -d -t nxb-151-broken-XXXXXX)"
rmdir -- "$broken_workspace"

record_gate workspace_init "$binary" workspace init --workspace "$workspace" --name 'Linux Acceptance' --json
record_gate workspace_doctor "$binary" workspace doctor --workspace "$workspace" --json
record_gate workspace_status "$binary" workspace status --workspace "$workspace" --json

printf 'occupied' > "$nonempty_workspace/existing.txt"
record_expected_failure init_rejects_nonempty 10 "$binary" workspace init --workspace "$nonempty_workspace" --json

cp -a -- "$workspace" "$broken_workspace"
rm -rf -- "$broken_workspace/evidence"
record_expected_failure doctor_detects_missing_directory 20 "$binary" workspace doctor --workspace "$broken_workspace" --json

binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
evidence_directory="$repo_root/target/nxb-validation"
mkdir -p -- "$evidence_directory"
evidence_path="$evidence_directory/nxb-151-linux-$head_sha.json"

python3 - "$results_file" "$evidence_path" "$head_sha" "$rustc_version" "$cargo_version" "$rustfmt_version" "$clippy_version" "$binary_sha256" <<'PY'
import csv
import json
import sys
from datetime import datetime, timezone

results_path, output_path, head, rustc, cargo, rustfmt, clippy, binary_sha = sys.argv[1:]
results = []
with open(results_path, newline='', encoding='utf-8') as handle:
    for name, exit_code, started, finished, command in csv.reader(handle, delimiter='\t'):
        results.append({
            'name': name,
            'command': command,
            'exit_code': int(exit_code),
            'started_at': started,
            'finished_at': finished,
            'passed': int(exit_code) == 0 or name in {
                'init_rejects_nonempty',
                'doctor_detects_missing_directory',
            },
        })

evidence = {
    'schema_version': 1,
    'milestone': 'NXB-151',
    'platform': 'linux',
    'head_sha': head,
    'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
    'toolchain': {
        'rustc': rustc,
        'cargo': cargo,
        'rustfmt': rustfmt,
        'clippy': clippy,
    },
    'nxb_binary_sha256': binary_sha,
    'results': results,
}
with open(output_path, 'w', encoding='utf-8', newline='\n') as handle:
    json.dump(evidence, handle, indent=2, sort_keys=True)
    handle.write('\n')
PY

printf 'NXB-151 single-binary Linux workspace validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Evidence: %s\n' "$evidence_path"
