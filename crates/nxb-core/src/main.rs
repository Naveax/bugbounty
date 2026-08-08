mod demo;
mod live_orchestrator;
mod scan;
mod workspace_facade;

use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use demo::{
    build_demo_receipt, default_demo_output, read_demo_receipt, verify_demo_receipt,
    write_demo_receipt, MILESTONE_END, MILESTONE_START, WORKSPACE_CRATE_COUNT,
};
use live_orchestrator::{
    hash_bytes, read_hex_file, read_json, write_json, LiveActivationCertificate,
    LiveActivationPayload, LiveRunPlan, PlannedMethod,
};
use nxb_events::EventEnvelope;
use nxb_policy::{is_public_destination, TargetPolicy};
use scan::ScanArgs;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "nxb", version, about = "NXBounty safety-contract utilities")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize, diagnose, inspect and migrate a local NXBounty workspace.
    Workspace(workspace_facade::WorkspaceArgs),
    /// Create, validate, inspect and disable authorization-bound target profiles.
    Target(target::TargetArgs),
    /// Build and verify externally signed single-binary release manifests.
    Release(release_manifest::ReleaseArgs),
    /// Build a bounded networkless scan plan and optional passive snapshot report.
    Scan(ScanArgs),
    /// Parse and compile a target policy without making network requests.
    ValidatePolicy {
        path: PathBuf,
        /// Override current time using RFC3339, primarily for deterministic fixtures.
        #[arg(long)]
        now: Option<String>,
    },
    /// Parse and validate one canonical event JSON document.
    ValidateEvent { path: PathBuf },
    /// Check whether an IP is public according to the default egress guard.
    CheckDestination { ip: IpAddr },
    /// Print the contract-complete repository profile.
    SystemStatus,
    /// Generate and verify a deterministic networkless architecture smoke receipt.
    DemoRun {
        /// Receipt output path. Defaults to target/nxb-demo-receipt.json.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a previously generated architecture smoke receipt.
    VerifyDemo { path: PathBuf },
    /// Build a signed-activation-ready, networkless live-run plan.
    LivePlan {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        selected_ip: IpAddr,
        #[arg(long = "resolved-ip", required = true)]
        resolved_ips: Vec<IpAddr>,
        #[arg(long, value_enum)]
        method: PlannedMethod,
        #[arg(long)]
        dns_context_id: String,
        #[arg(long)]
        dns_resolver_id: String,
        #[arg(long, default_value_t = 60)]
        dns_ttl_seconds: u32,
        #[arg(long)]
        activation_public_key: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Verify a networkless live-run plan.
    VerifyLivePlan {
        path: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Emit canonical bytes for an external Ed25519 activation signature.
    LiveActivationTemplate {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation_id: String,
        #[arg(long)]
        not_before: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify an externally signed activation certificate.
    VerifyLiveActivation {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Execute one exact HTTPS GET/HEAD request. Compiled only with live-network.
    #[cfg(feature = "live-network")]
    LiveRun {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        state_directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        findings_output: PathBuf,
        #[arg(long)]
        enable_live: bool,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct ActivationTemplateDocument {
    payload: LiveActivationPayload,
    signing_payload_hex: String,
    signing_payload_sha256: String,
    signature_hex: String,
}

#[cfg(feature = "live-network")]
#[derive(Debug, Serialize)]
struct LiveRunOutputDocument {
    receipt: live_orchestrator::LiveOrchestratorReceipt,
    findings: Vec<nxb_passive_analyzers::Finding>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Workspace(args) => return workspace_facade::run(args),
        Command::Target(args) => return target::run(args),
        Command::Release(args) => return release_manifest::run(args),
        Command::Scan(args) => scan::run(args),
        Command::ValidatePolicy { path, now } => validate_policy(path, now),
        Command::ValidateEvent { path } => validate_event(path),
        Command::CheckDestination { ip } => check_destination(ip),
        Command::SystemStatus => system_status(),
        Command::DemoRun { output } => demo_run(output),
        Command::VerifyDemo { path } => verify_demo(path),
        Command::LivePlan {
            policy,
            target,
            selected_ip,
            resolved_ips,
            method,
            dns_context_id,
            dns_resolver_id,
            dns_ttl_seconds,
            activation_public_key,
            run_id,
            expires_at,
            output,
            now,
        } => live_plan(
            policy,
            target,
            selected_ip,
            resolved_ips,
            method,
            dns_context_id,
            dns_resolver_id,
            dns_ttl_seconds,
            activation_public_key,
            run_id,
            expires_at,
            output,
            now,
        ),
        Command::VerifyLivePlan { path, now } => verify_live_plan(path, now),
        Command::LiveActivationTemplate {
            plan,
            activation_id,
            not_before,
            expires_at,
            output,
        } => live_activation_template(plan, activation_id, not_before, expires_at, output),
        Command::VerifyLiveActivation {
            plan,
            activation,
            public_key,
            now,
        } => verify_live_activation(plan, activation, public_key, now),
        #[cfg(feature = "live-network")]
        Command::LiveRun {
            policy,
            plan,
            activation,
            public_key,
            state_directory,
            output,
            findings_output,
            enable_live,
            now,
        } => live_run(
            policy,
            plan,
            activation,
            public_key,
            state_directory,
            output,
            findings_output,
            enable_live,
            now,
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NXB-CLI-1: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn validate_policy(path: PathBuf, now: Option<String>) -> Result<()> {
    let input = fs::read_to_string(&path)
        .with_context(|| format!("could not read policy file {}", path.display()))?;
    let now = parse_now(now)?;

    let policy = TargetPolicy::from_toml(&input)?;
    let compiled = policy.compile(now)?;

    println!("policy: valid");
    println!("program: {}", compiled.program_name());
    println!("included_hosts: {}", compiled.included_host_count());
    println!(
        "maximum_total_requests: {}",
        compiled.maximum_total_requests()
    );
    Ok(())
}

fn validate_event(path: PathBuf) -> Result<()> {
    let input = fs::read_to_string(&path)
        .with_context(|| format!("could not read event file {}", path.display()))?;
    let event = EventEnvelope::from_json(&input)?;
    event.validate()?;

    println!("event: valid");
    println!("event_id: {}", event.event_id);
    println!("run_id: {}", event.run_id);
    Ok(())
}

fn check_destination(ip: IpAddr) -> Result<()> {
    if !is_public_destination(ip) {
        bail!("destination is denied by the default public-egress guard: {ip}");
    }

    println!("destination: public");
    println!("ip: {ip}");
    Ok(())
}

fn system_status() -> Result<()> {
    let receipt = build_demo_receipt()?;
    println!("status: contract-complete");
    println!("milestones: NXB-{MILESTONE_START}..NXB-{MILESTONE_END}");
    println!("workspace_crates: {WORKSPACE_CRATE_COUNT}");
    println!("execution_mode: synthetic-networkless-by-default");
    println!("live_network_adapter: implemented");
    println!(
        "live_orchestrator: {}",
        if cfg!(feature = "live-network") {
            "compiled-explicit-activation-required"
        } else {
            "disabled-at-compile-time"
        }
    );
    println!("operator_scan: bounded-networkless-default");
    println!("demo_tail_sha256: {}", receipt.tail_hash);
    Ok(())
}

fn demo_run(output: Option<PathBuf>) -> Result<()> {
    let output = output.unwrap_or_else(default_demo_output);
    let receipt = build_demo_receipt()?;
    write_demo_receipt(&output, &receipt)?;
    println!("demo: valid");
    println!("mode: {}", receipt.mode);
    println!("stages: {}", receipt.stage_count);
    println!("tail_sha256: {}", receipt.tail_hash);
    println!("receipt: {}", output.display());
    Ok(())
}

fn verify_demo(path: PathBuf) -> Result<()> {
    let receipt = read_demo_receipt(&path)?;
    verify_demo_receipt(&receipt)?;
    println!("demo_receipt: valid");
    println!("stages: {}", receipt.stage_count);
    println!("tail_sha256: {}", receipt.tail_hash);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn live_plan(
    policy: PathBuf,
    target: String,
    selected_ip: IpAddr,
    resolved_ips: Vec<IpAddr>,
    method: PlannedMethod,
    dns_context_id: String,
    dns_resolver_id: String,
    dns_ttl_seconds: u32,
    activation_public_key: PathBuf,
    run_id: String,
    expires_at: String,
    output: PathBuf,
    now: Option<String>,
) -> Result<()> {
    let policy_bytes =
        fs::read(&policy).with_context(|| format!("could not read {}", policy.display()))?;
    let now = parse_now(now)?;
    let expires_at = parse_timestamp(&expires_at)?;
    let public_key = read_hex_file(&activation_public_key, "activation_public_key")?;
    if public_key.len() != 32 {
        bail!("activation public key must contain 32 Ed25519 bytes");
    }
    let mut resolved_ips = resolved_ips.into_iter().collect::<BTreeSet<_>>();
    resolved_ips.insert(selected_ip);

    let plan = LiveRunPlan::build(
        run_id,
        now,
        expires_at,
        &policy_bytes,
        target,
        selected_ip,
        resolved_ips,
        method,
        dns_context_id,
        dns_resolver_id,
        dns_ttl_seconds,
        &public_key,
    )?;
    plan.verify(now)?;
    write_json(&output, &plan)?;
    println!("live_plan: valid");
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_live_plan(path: PathBuf, now: Option<String>) -> Result<()> {
    let now = parse_now(now)?;
    let plan: LiveRunPlan = read_json(&path)?;
    plan.verify(now)?;
    println!("live_plan: valid");
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("maximum_requests: {}", plan.maximum_requests);
    Ok(())
}

fn live_activation_template(
    plan: PathBuf,
    activation_id: String,
    not_before: String,
    expires_at: String,
    output: PathBuf,
) -> Result<()> {
    let plan: LiveRunPlan = read_json(&plan)?;
    let not_before = parse_timestamp(&not_before)?;
    let expires_at = parse_timestamp(&expires_at)?;
    let payload = LiveActivationPayload::template(activation_id, &plan, not_before, expires_at)?;
    let signing_bytes = payload.signing_bytes()?;
    let document = ActivationTemplateDocument {
        payload,
        signing_payload_hex: lower_hex(&signing_bytes),
        signing_payload_sha256: hash_bytes(&signing_bytes),
        signature_hex: String::new(),
    };
    write_json(&output, &document)?;
    println!("activation_template: valid");
    println!(
        "signing_payload_sha256: {}",
        document.signing_payload_sha256
    );
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_live_activation(
    plan: PathBuf,
    activation: PathBuf,
    public_key: PathBuf,
    now: Option<String>,
) -> Result<()> {
    let plan: LiveRunPlan = read_json(&plan)?;
    let activation: LiveActivationCertificate = read_json(&activation)?;
    let public_key = read_hex_file(&public_key, "public_key")?;
    let now = parse_now(now)?;
    activation.verify(&plan, &public_key, now)?;
    println!("live_activation: valid");
    println!(
        "activation_certificate_sha256: {}",
        activation.certificate_sha256()?
    );
    println!("maximum_requests: {}", activation.payload.maximum_requests);
    Ok(())
}

#[cfg(feature = "live-network")]
#[allow(clippy::too_many_arguments)]
fn live_run(
    policy: PathBuf,
    plan: PathBuf,
    activation: PathBuf,
    public_key: PathBuf,
    state_directory: PathBuf,
    output: PathBuf,
    findings_output: PathBuf,
    enable_live: bool,
    now: Option<String>,
) -> Result<()> {
    if !enable_live {
        bail!("live execution requires the explicit --enable-live flag");
    }
    let policy_bytes =
        fs::read(&policy).with_context(|| format!("could not read {}", policy.display()))?;
    let plan: LiveRunPlan = read_json(&plan)?;
    let activation: LiveActivationCertificate = read_json(&activation)?;
    let public_key = read_hex_file(&public_key, "public_key")?;
    let now = parse_now(now)?;
    let (receipt, findings) = live_orchestrator::execute_live_run(
        &policy_bytes,
        &plan,
        &activation,
        &public_key,
        &state_directory,
        now,
    )?;
    let document = LiveRunOutputDocument {
        receipt: receipt.clone(),
        findings: findings.clone(),
    };
    write_json(&output, &document)?;
    write_json(&findings_output, &findings)?;
    println!("live_run: completed");
    println!("plan_sha256: {}", receipt.plan_sha256);
    println!("findings: {}", receipt.finding_count);
    println!("redirect_followed: false");
    println!("output: {}", output.display());
    println!("findings_output: {}", findings_output.display());
    Ok(())
}

fn parse_now(value: Option<String>) -> Result<DateTime<Utc>> {
    match value {
        Some(value) => parse_timestamp(&value),
        None => Ok(Utc::now()),
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
        .map(|value| value.with_timezone(&Utc))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
