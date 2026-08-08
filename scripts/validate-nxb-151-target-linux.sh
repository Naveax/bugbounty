#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
workspace=""
output_dir=""
cleanup() {
  [[ -n "$workspace" ]] && rm -rf -- "$workspace"
  [[ -n "$output_dir" ]] && rm -rf -- "$output_dir"
}
trap cleanup EXIT

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'invalid Git HEAD' >&2; exit 1; }
[[ -z "$(git status --porcelain=v1)" ]] || { echo 'working tree must be clean' >&2; exit 1; }
rustc_version="$(rustc --version)"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] || {
  printf 'expected rustc 1.97.1, found %s\n' "$rustc_version" >&2
  exit 1
}

cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
cargo build -p nxb-core --bin nxb --all-features --locked

nxb="$repo_root/target/debug/nxb"
[[ -x "$nxb" ]] || { echo 'nxb binary is missing' >&2; exit 1; }

workspace="$(mktemp -d -t nxb-151-target-XXXXXX)"
rmdir -- "$workspace"
output_dir="$(mktemp -d -t nxb-151-target-output-XXXXXX)"
policy="$output_dir/target-policy.toml"
authorization="$output_dir/authorization.txt"

cat >"$policy" <<'EOF'
schema_version = 1

[program]
name = "Example Program"
platform = "hackerone"
policy_url = "https://hackerone.com/example"

[scope]
include_hosts = ["example.org"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD", "OPTIONS"]
allow_subdomains = false

[automation]
active_testing = false
credential_bruteforce = false
destructive_testing = false
oob_callbacks = false
max_requests_per_second = 1.0
max_concurrency = 1
max_total_requests = 10

[authorization]
confirmed = true
researcher = "acceptance-researcher"
policy_snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expires_at = 2099-01-01T00:00:00Z
EOF
printf 'Bearer secret-that-must-never-be-persisted\n' >"$authorization"

expect_exit() {
  local expected="$1"
  shift
  set +e
  "$@" >"$output_dir/expected-$expected.out" 2>"$output_dir/expected-$expected.err"
  local actual=$?
  set -e
  [[ $actual -eq $expected ]] || {
    printf 'command returned %s; expected %s: %q\n' "$actual" "$expected" "$*" >&2
    cat "$output_dir/expected-$expected.err" >&2 || true
    exit 1
  }
}

create_args=(
  --authorization-reference hackerone/program/example#scope-2026
  --authorization-document "$authorization"
  --policy "$policy"
)

"$nxb" workspace init \
  --workspace "$workspace" \
  --name 'Target Linux Acceptance' \
  --json >"$output_dir/init.json"

"$nxb" target create \
  --workspace "$workspace" \
  --id example-app \
  --name 'Example App' \
  --origin 'https://example.org' \
  --include-path /api \
  --exclude-path /api/logout \
  "${create_args[@]}" \
  --json >"$output_dir/create.json"
"$nxb" target validate \
  --workspace "$workspace" \
  --id example-app \
  --authorization-document "$authorization" \
  --policy "$policy" \
  --json >"$output_dir/validate.json"
"$nxb" target list --workspace "$workspace" --json >"$output_dir/list.json"
"$nxb" target show --workspace "$workspace" --id example-app --json >"$output_dir/show.json"

python3 - "$output_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
created = json.loads((root / 'create.json').read_text())
validated = json.loads((root / 'validate.json').read_text())
listed = json.loads((root / 'list.json').read_text())
shown = json.loads((root / 'show.json').read_text())
assert created['status'] == 'active'
assert created['origin'] == 'https://example.org'
assert created['allowed_methods'] == ['GET', 'HEAD', 'OPTIONS']
assert created['program']['platform'] == 'hackerone'
assert len(created['authorization_sha256']) == 64
assert len(created['policy_sha256']) == 64
assert len(created['identity_sha256']) == 64
assert validated['validation']['status'] == 'valid'
assert listed['status'] == 'ready'
assert listed['network_activity'] == 'none'
assert listed['count'] == 1
assert shown['target_id'] == 'example-app'
assert shown['include_paths'] == ['/api']
assert shown['exclude_paths'] == ['/api/logout']
assert shown['authorization_reference'] == 'hackerone/program/example#scope-2026'
PY

profile="$workspace/targets/example-app.json"
receipt="$workspace/targets/example-app.disabled.json"
[[ "$(stat -c '%a' "$profile")" == '600' ]] || { echo 'target profile mode is not 0600' >&2; exit 1; }
if grep -Fq 'secret-that-must-never-be-persisted' "$profile" \
  || grep -Fq "$policy" "$profile" \
  || grep -Fq "$authorization" "$profile"; then
  echo 'target profile persisted secret bytes or source paths' >&2
  exit 1
fi

for origin in \
  'http://example.org' \
  'https://user@example.org' \
  'https://127.0.0.1' \
  'https://service.internal' \
  'https://*.example.org'; do
  expect_exit 50 "$nxb" target create \
    --workspace "$workspace" \
    --id invalid-origin \
    --name 'Invalid Origin' \
    --origin "$origin" \
    "${create_args[@]}" \
    --json
done
expect_exit 50 "$nxb" target create \
  --workspace "$workspace" \
  --id invalid-path \
  --name 'Invalid Path' \
  --origin 'https://example.org' \
  --include-path '/api%2fadmin' \
  "${create_args[@]}" \
  --json
expect_exit 50 "$nxb" target create \
  --workspace "$workspace" \
  --id invalid-reference \
  --name 'Invalid Reference' \
  --origin 'https://example.org' \
  --authorization-reference 'https://example.org/scope?token=secret' \
  --authorization-document "$authorization" \
  --policy "$policy" \
  --json

cp -- "$profile" "$output_dir/profile.original"
python3 - "$profile" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value['name'] = 'Tampered Target'
path.write_text(json.dumps(value, indent=2) + '\n')
PY
chmod 600 "$profile"
expect_exit 52 "$nxb" target show --workspace "$workspace" --id example-app --json
cp -- "$output_dir/profile.original" "$profile"
chmod 600 "$profile"

cp -- "$authorization" "$output_dir/authorization.original"
printf 'different authorization\n' >"$authorization"
expect_exit 54 "$nxb" target validate \
  --workspace "$workspace" \
  --id example-app \
  --authorization-document "$authorization" \
  --policy "$policy" \
  --json
cp -- "$output_dir/authorization.original" "$authorization"

"$nxb" target disable \
  --workspace "$workspace" \
  --id example-app \
  --reason operator-hold \
  --json >"$output_dir/disable.json"
"$nxb" target list --workspace "$workspace" --json >"$output_dir/active.json"
"$nxb" target list --workspace "$workspace" --include-disabled --json >"$output_dir/all.json"
[[ "$(stat -c '%a' "$receipt")" == '600' ]] || { echo 'disable receipt mode is not 0600' >&2; exit 1; }

python3 - "$output_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
disabled = json.loads((root / 'disable.json').read_text())
active = json.loads((root / 'active.json').read_text())
all_targets = json.loads((root / 'all.json').read_text())
assert disabled['status'] == 'disabled'
assert disabled['disabled_reason'] == 'operator_hold'
assert active['count'] == 0
assert all_targets['count'] == 1
assert all_targets['targets'][0]['status'] == 'disabled'
PY

cp -- "$receipt" "$output_dir/receipt.original"
python3 - "$receipt" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value['profile_sha256'] = '0' * 64
path.write_text(json.dumps(value, indent=2) + '\n')
PY
chmod 600 "$receipt"
expect_exit 52 "$nxb" target show --workspace "$workspace" --id example-app --json
cp -- "$output_dir/receipt.original" "$receipt"
chmod 600 "$receipt"

printf '{}\n' >"$workspace/state/migration-active.json"
chmod 600 "$workspace/state/migration-active.json"
expect_exit 51 "$nxb" target list --workspace "$workspace" --json
rm -f -- "$workspace/state/migration-active.json"
"$nxb" target show --workspace "$workspace" --id example-app --json >/dev/null

validation_dir="$repo_root/target/nxb-validation"
mkdir -p -- "$validation_dir"
evidence="$validation_dir/nxb-151-target-linux-$head_sha.json"
python3 - "$evidence" "$head_sha" "$rustc_version" "$nxb" <<'PY'
import hashlib, json, pathlib, sys
output, head, rustc, binary = sys.argv[1:]
value = {
    'schema_version': 1,
    'milestone': 'NXB-151',
    'gate': 'authorization_bound_target_profiles',
    'platform': 'linux',
    'head_sha': head,
    'rustc': rustc,
    'binary_sha256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
    'checks': {
        'create_validate_list_show_disable': 'passed',
        'authorization_and_policy_binding': 'passed',
        'secret_and_source_path_non_persistence': 'passed',
        'origin_path_and_reference_rejection': 'passed',
        'identity_tamper_rejection': 'passed',
        'source_digest_drift_exit_54': 'passed',
        'receipt_tamper_rejection': 'passed',
        'pending_migration_exit_51': 'passed',
        'private_file_modes': 'passed',
        'network_activity': 'none',
    },
}
pathlib.Path(output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
PY

printf 'NXB-151 authorization-bound target Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Evidence: %s\n' "$evidence"
