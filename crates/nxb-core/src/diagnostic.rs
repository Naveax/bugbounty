use std::io::{self, Write};

use anyhow::Error;
use serde::Serialize;

const DIAGNOSTIC_SCHEMA_VERSION: u32 = 1;
const MAX_MESSAGE_CHARACTERS: usize = 2_048;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DiagnosticSpec {
    pub(crate) code: &'static str,
    pub(crate) domain: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) text_prefix: &'static str,
}

#[derive(Debug, Serialize)]
struct DiagnosticDocument<'a> {
    schema_version: u32,
    status: &'static str,
    code: &'a str,
    domain: &'a str,
    operation: &'a str,
    exit_code: u8,
    message: &'a str,
}

pub(crate) fn emit_failure(spec: DiagnosticSpec, exit_code: u8, json_output: bool, error: &Error) {
    let message = bounded_message(error);
    if json_output {
        let document = DiagnosticDocument {
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
            status: "error",
            code: spec.code,
            domain: spec.domain,
            operation: spec.operation,
            exit_code,
            message: &message,
        };
        let mut stderr = io::stderr().lock();
        if serde_json::to_writer(&mut stderr, &document).is_ok() {
            let _ = stderr.write_all(b"\n");
            return;
        }
    }
    eprintln!(
        "{} [{}] domain={} operation={}: {}",
        spec.text_prefix, spec.code, spec.domain, spec.operation, message
    );
}

fn bounded_message(error: &Error) -> String {
    let rendered = format!("{error:#}");
    let mut message = rendered
        .chars()
        .filter(|value| !matches!(value, '\r' | '\n' | '\0'))
        .take(MAX_MESSAGE_CHARACTERS)
        .collect::<String>();
    if message.is_empty() {
        message.push_str("operation failed without a diagnostic message");
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_message_is_single_line_and_bounded() {
        let input = anyhow::anyhow!("first\nsecond\rthird\0{}", "x".repeat(4_096));
        let message = bounded_message(&input);
        assert!(!message
            .chars()
            .any(|value| matches!(value, '\n' | '\r' | '\0')));
        assert!(message.chars().count() <= MAX_MESSAGE_CHARACTERS);
    }
}
