//! End-to-end tests: run the compiled binary against certificate fixtures.
//! Fixtures are self-signed test certificates whose private keys were discarded.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pqc-scan"))
        .args(args)
        .output()
        .expect("failed to run pqc-scan")
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn json(args: &[&str]) -> serde_json::Value {
    let out = run(args);
    serde_json::from_slice(&out.stdout).expect("stdout is not valid JSON")
}

/// Severity of the first finding matching `what` in the first certificate of the first report.
fn severity_of(report: &serde_json::Value, what: &str) -> String {
    report[0]["certificates"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["what"] == what)
        .unwrap_or_else(|| panic!("no '{what}' finding"))["severity"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn rsa_2048_is_quantum_vulnerable() {
    let r = json(&["cert", &fixture("rsa2048.pem"), "--json"]);
    assert_eq!(severity_of(&r, "public key"), "vulnerable");
    assert_eq!(
        r[0]["certificates"][0]["findings"][0]["algorithm"],
        "RSA-2048"
    );
}

#[test]
fn ec_p256_is_quantum_vulnerable() {
    let r = json(&["cert", &fixture("ec-p256.pem"), "--json"]);
    assert_eq!(severity_of(&r, "public key"), "vulnerable");
}

#[test]
fn ed25519_is_quantum_vulnerable() {
    let r = json(&["cert", &fixture("ed25519.pem"), "--json"]);
    assert_eq!(severity_of(&r, "public key"), "vulnerable");
}

#[test]
fn rsa_1024_is_critical() {
    let r = json(&["cert", &fixture("rsa1024-sha1.pem"), "--json"]);
    assert_eq!(severity_of(&r, "public key"), "critical");
}

#[test]
fn fail_on_controls_exit_code() {
    let rsa2048 = fixture("rsa2048.pem");
    let rsa1024 = fixture("rsa1024-sha1.pem");

    // quantum-vulnerable finding trips --fail-on vulnerable but not --fail-on critical
    assert_eq!(
        run(&["cert", &rsa2048, "--fail-on", "vulnerable"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        run(&["cert", &rsa2048, "--fail-on", "critical"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&["cert", &rsa1024, "--fail-on", "critical"])
            .status
            .code(),
        Some(1)
    );
    // without --fail-on the exit code is always 0 on a successful scan
    assert_eq!(run(&["cert", &rsa1024]).status.code(), Some(0));
}

#[test]
fn text_output_mentions_pqc_migration() {
    let out = run(&["cert", &fixture("rsa2048.pem")]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("QUANTUM-VULNERABLE"));
    assert!(text.contains("ML-DSA"));
    assert!(text.contains("Summary:"));
}

#[test]
fn missing_file_exits_2() {
    let out = run(&["cert", "/nonexistent/file.pem"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

#[test]
fn non_certificate_file_exits_2() {
    let out = run(&[
        "cert",
        &format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR")),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no certificates found"));
}
