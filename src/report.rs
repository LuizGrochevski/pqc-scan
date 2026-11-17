//! Report model and terminal rendering.

use std::fmt::Write;
use std::io::IsTerminal;

use serde::Serialize;

use crate::cert::CertReport;
use crate::classify::{Finding, Severity};

#[derive(Debug, Serialize)]
pub struct TlsSummary {
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub tls: Option<TlsSummary>,
    /// Connection-level findings (e.g. key exchange).
    pub findings: Vec<Finding>,
    pub certificates: Vec<CertReport>,
}

impl Report {
    fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .chain(self.certificates.iter().flat_map(|c| c.findings.iter()))
    }

    pub fn worst(&self) -> Severity {
        self.all_findings()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Safe)
    }

    pub fn render(&self, color: bool) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{}",
            paint(&format!("pqc-scan · {}", self.target), "1", color)
        );
        if let Some(t) = &self.tls {
            let _ = writeln!(
                out,
                "{} · {} · key exchange: {}",
                t.version,
                t.cipher_suite,
                t.key_exchange.as_deref().unwrap_or("unknown")
            );
        }
        let _ = writeln!(out);

        if !self.findings.is_empty() {
            let _ = writeln!(out, "{}", paint("Connection", "1", color));
            for f in &self.findings {
                render_finding(&mut out, f, color);
            }
            let _ = writeln!(out);
        }

        for c in &self.certificates {
            let _ = writeln!(
                out,
                "{}",
                paint(
                    &format!("Certificate #{} ({}) — {}", c.index, c.role, c.subject),
                    "1",
                    color
                )
            );
            let _ = writeln!(out, "  issuer:  {}", c.issuer);
            let _ = writeln!(out, "  expires: {}", c.not_after);
            for f in &c.findings {
                render_finding(&mut out, f, color);
            }
            let _ = writeln!(out);
        }

        let count = |s: Severity| self.all_findings().filter(|f| f.severity == s).count();
        let _ = writeln!(
            out,
            "Summary: {} critical · {} quantum-vulnerable · {} info · {} quantum-safe",
            count(Severity::Critical),
            count(Severity::Vulnerable),
            count(Severity::Info),
            count(Severity::Safe),
        );
        out
    }
}

fn render_finding(out: &mut String, f: &Finding, color: bool) {
    let tag = paint(
        &format!("[{}]", f.severity.label()),
        severity_code(f.severity),
        color,
    );
    let _ = writeln!(out, "  {tag} {}: {}", f.what, f.algorithm);
    let _ = writeln!(out, "      {}", f.detail);
    if let Some(r) = &f.recommendation {
        let _ = writeln!(out, "      → {r}");
    }
}

fn severity_code(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "1;31",
        Severity::Vulnerable => "33",
        Severity::Info => "36",
        Severity::Safe => "32",
    }
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}
