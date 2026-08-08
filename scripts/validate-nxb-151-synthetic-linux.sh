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
policy="$repo_root/fixtures/nxb-151/synthetic-policy.toml"
authorization="$repo_root/fixtures/nxb-151/synthetic-authorization.txt"
[[ -x "$nxb" && -f "$policy" && -f "$authorization" ]] || {
  echo 'synthetic acceptance inputs are missing' >&2
  exit 1
}

workspace="$(mktemp -d -t nxb-151-synthetic-XXXXXX)"
rmdir -- "$workspace"
output_dir="$(mktemp -d -t nxb-151-synthetic-output-XXXXXX)"
scan_output="$workspace/reports/synthetic-run"
demo_receipt="$workspace/reports/demo-receipt.json"
now='2026-08-05T12:00:00Z'

"$nxb" workspace init \
  --workspace "$workspace" \
  --name 'NXB Synthetic Product' \
  --json > "$output_dir/init.json"
"$nxb" workspace doctor --workspace "$workspace" --json > "$output_dir/doctor-before.json"
"$nxb" target create \
  --workspace "$workspace" \
  --id synthetic-example \
  --name 'Synthetic Example' \
  --origin 'https://example.org' \
  --include-path / \
  --exclude-path /logout \
  --authorization-reference 'local_fixture/nxb-151#synthetic' \
  --authorization-document "$authorization" \
  --policy "$policy" \
  --json > "$output_dir/target.json"
"$nxb" target validate \
  --workspace "$workspace" \
  --id synthetic-example \
  --authorization-document "$authorization" \
  --policy "$policy" \
  --json > "$output_dir/target-validate.json"
"$nxb" target list --workspace "$workspace" --json > "$output_dir/target-list.json"
"$nxb" validate-policy --path "$policy" --now "$now" > "$output_dir/policy.txt"
"$nxb" scan \
  --program "$policy" \
  --target 'https://example.org/' \
  --output-directory "$scan_output" \
  --run-id synthetic-run-001 \
  --maximum-depth 1 \
  --maximum-endpoints 16 \
  --maximum-requests 8 \
  --dry-run true \
  --now "$now" > "$output_dir/scan.txt"
"$nxb" demo-run --output "$demo_receipt" > "$output_dir/demo.txt"
"$nxb" verify-demo "$demo_receipt" > "$output_dir/verify-demo.txt"
"$nxb" workspace doctor --workspace "$workspace" --json > "$output_dir/doctor-after.json"
"$nxb" workspace status --workspace "$workspace" --json > "$output_dir/status.json"
"$nxb" system-status > "$output_dir/system-status.txt"

for artifact in \
  "$scan_output/scan-plan.json" \
  "$scan_output/report.json" \
  "$scan_output/report.md" \
  "$scan_output/hackerone-draft.md" \
  "$scan_output/manifest.json" \
  "$demo_receipt"; do
  [[ -f "$artifact" ]] || { printf 'missing synthetic artifact: %s\n' "$artifact" >&2; exit 1; }
done

python3 - \
  "$output_dir/init.json" \
  "$output_dir/doctor-before.json" \
  "$output_dir/target.json" \
  "$output_dir/target-validate.json" \
  "$output_dir/target-list.json" \
  "$workspace/targets/synthetic-example.json" \
  "$policy" \
  "$authorization" \
  "$scan_output/scan-plan.json" \
  "$scan_output/report.json" \
  "$scan_output/manifest.json" \
  "$output_dir/doctor-after.json" \
  "$output_dir/status.json" <<'PY'
import json, pathlib, sys
(
    init_path,
    doctor_before_path,
    target_path,
    target_validate_path,
    target_list_path,
    profile_path,
    policy_path,
    authorization_path,
    plan_path,
    report_path,
    manifest_path,
    doctor_after_path,
    status_path,
) = map(pathlib.Path, sys.argv[1:])
initialized = json.loads(init_path.read_text())
doctor_before = json.loads(doctor_before_path.read_text())
target = json.loads(target_path.read_text())
target_validation = json.loads(target_validate_path.read_text())
targets = json.loads(target_list_path.read_text())
profile_text = profile_path.read_text()
plan = json.loads(plan_path.read_text())
report = json.loads(report_path.read_text())
manifest = json.loads(manifest_path.read_text())
doctor_after = json.loads(doctor_after_path.read_text())
status = json.loads(status_path.read_text())
assert initialized['status'] == 'initialized'
assert doctor_before['status'] == 'healthy'
assert target['status'] == 'active'
assert target['origin'] == 'https://example.org'
assert target['network_activity'] == 'none'
assert target['authorization_reference'] == 'local_fixture/nxb-151#synthetic'
assert target['program']['platform'] == 'local_fixture'
assert len(target['authorization_sha256']) == 64
assert len(target['policy_sha256']) == 64
assert len(target['identity_sha256']) == 64
assert target_validation['validation']['status'] == 'valid'
assert target_validation['validation']['authorization_sha256'] == target['authorization_sha256']
assert target_validation['validation']['policy_sha256'] == target['policy_sha256']
assert policy_path.read_text() not in profile_text
assert authorization_path.read_text() not in profile_text
assert str(policy_path) not in profile_text
assert str(authorization_path) not in profile_text
assert targets['count'] == 1
assert targets['network_activity'] == 'none'
assert plan['version'] == 1
assert plan['run_id'] == 'synthetic-run-001'
assert plan['target_url'] == 'https://example.org/'
assert plan['dry_run'] is True
assert plan['network_activity'] == 'none'
assert plan['scheduler']['issued'] == 0
assert report['run_id'] == 'synthetic-run-001'
assert report['automatic_submission'] is False
assert report['findings'] == []
assert manifest['version'] == 1
assert set(manifest['entries']) == {'report.json', 'report.md', 'hackerone-draft.md'}
assert doctor_after['status'] == 'healthy'
assert status['status'] == 'ready'
PY

grep -q '^network_activity: none$' "$output_dir/scan.txt"
grep -q '^No candidate findings are available for submission\.$' "$scan_output/hackerone-draft.md"
grep -q 'NXB does not submit reports automatically' "$scan_output/hackerone-draft.md"
grep -q '^demo_receipt: valid$' "$output_dir/verify-demo.txt"
grep -q '^status: contract-complete$' "$output_dir/system-status.txt"

validation_dir="$repo_root/target/nxb-validation"
mkdir -p -- "$validation_dir"
evidence="$validation_dir/nxb-151-synthetic-linux-$head_sha.json"
python3 - \
  "$evidence" "$head_sha" "$rustc_version" "$nxb" \
  "$workspace/targets/synthetic-example.json" \
  "$scan_output/scan-plan.json" "$scan_output/report.json" \
  "$scan_output/manifest.json" "$demo_receipt" <<'PY'
import hashlib, json, pathlib, sys
output, head, rustc, binary, target_profile, plan, report, manifest, demo = sys.argv[1:]
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
value = {
    'schema_version': 1,
    'milestone': 'NXB-151',
    'gate': 'synthetic_product_flow',
    'platform': 'linux',
    'head_sha': head,
    'rustc': rustc,
    'binary_sha256': digest(binary),
    'artifacts': {
        'target_profile_sha256': digest(target_profile),
        'scan_plan_sha256': digest(plan),
        'report_sha256': digest(report),
        'manifest_sha256': digest(manifest),
        'demo_receipt_sha256': digest(demo),
    },
    'checks': {
        'workspace': 'passed',
        'authorization_bound_target_profile': 'passed',
        'target_source_validation': 'passed',
        'policy_validation': 'passed',
        'networkless_scan': 'passed',
        'manual_report_bundle': 'passed',
        'demo_receipt': 'passed',
        'final_doctor_status': 'passed',
        'network_activity': 'none',
        'automatic_submission': False,
    },
}
pathlib.Path(output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
PY

printf 'NXB-151 synthetic Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Evidence: %s\n' "$evidence"
