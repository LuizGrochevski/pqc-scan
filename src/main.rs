mod cert;
mod classify;
mod report;
mod tls;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};

use classify::Severity;
use report::{Report, TlsSummary};

/// Audit TLS endpoints and X.509 certificates for quantum-vulnerable cryptography.
#[derive(Parser)]
#[command(name = "pqc-scan", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Handshake with a TLS endpoint and audit its key exchange and certificate chain
    Host {
        /// Target as host, host:port or https://host[:port] (default port 443)
        target: String,
        /// Connect/read timeout in seconds
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[command(flatten)]
        out: OutArgs,
    },
    /// Audit certificates stored in PEM or DER files
    Cert {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[command(flatten)]
        out: OutArgs,
    },
}

#[derive(Args)]
struct OutArgs {
    /// Print machine-readable JSON (always an array of reports)
    #[arg(long)]
    json: bool,
    /// Exit with status 1 if any finding reaches this severity (useful in CI)
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Vulnerable,
    Critical,
}

impl FailOn {
    fn threshold(self) -> Severity {
        match self {
            FailOn::Vulnerable => Severity::Vulnerable,
            FailOn::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let (reports, out) = match cli.cmd {
        Cmd::Host {
            target,
            timeout,
            out,
        } => (vec![scan_host(&target, Duration::from_secs(timeout))?], out),
        Cmd::Cert { files, out } => (scan_files(&files)?, out),
    };

    if out.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        let color = report::use_color();
        for r in &reports {
            print!("{}", r.render(color));
        }
    }

    let worst = reports
        .iter()
        .map(Report::worst)
        .max()
        .unwrap_or(Severity::Safe);
    Ok(match out.fail_on {
        Some(t) if worst >= t.threshold() => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

fn scan_host(target: &str, timeout: Duration) -> Result<Report> {
    let (host, port) = parse_target(target)?;
    let info = tls::probe(&host, port, timeout)
        .with_context(|| format!("TLS handshake with {host}:{port} failed"))?;

    let findings = info
        .key_exchange
        .as_deref()
        .map(classify::classify_kx_group)
        .into_iter()
        .collect();

    let certificates = info
        .chain
        .iter()
        .enumerate()
        .map(|(i, der)| cert::analyze_der(der, i))
        .collect::<Result<Vec<_>>>()?;

    Ok(Report {
        target: format!("{host}:{port}"),
        tls: Some(TlsSummary {
            version: info.version,
            cipher_suite: info.cipher_suite,
            key_exchange: info.key_exchange,
        }),
        findings,
        certificates,
    })
}

fn scan_files(files: &[PathBuf]) -> Result<Vec<Report>> {
    files
        .iter()
        .map(|path| {
            let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            let ders = cert::certs_from_bytes(&data);
            if ders.is_empty() {
                return Err(anyhow!("no certificates found in {}", path.display()));
            }
            let certificates = ders
                .iter()
                .enumerate()
                .map(|(i, der)| cert::analyze_der(der, i))
                .collect::<Result<Vec<_>>>()?;
            Ok(Report {
                target: path.display().to_string(),
                tls: None,
                findings: vec![],
                certificates,
            })
        })
        .collect()
}

fn parse_target(input: &str) -> Result<(String, u16)> {
    let s = input.trim();
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);

    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unterminated IPv6 literal in '{input}'"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| anyhow!("invalid port '{p}'"))?,
            None => 443,
        };
        (host.to_string(), port)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse().map_err(|_| anyhow!("invalid port '{p}'"))?,
            ),
            _ => (s.to_string(), 443),
        }
    };

    if host.is_empty() {
        return Err(anyhow!("missing host in '{input}'"));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::parse_target;

    #[test]
    fn parses_targets() {
        assert_eq!(
            parse_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_target("example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            parse_target("https://example.com/path").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(parse_target("[::1]:9443").unwrap(), ("::1".into(), 9443));
        assert_eq!(parse_target("[::1]").unwrap(), ("::1".into(), 443));
    }

    #[test]
    fn rejects_bad_targets() {
        assert!(parse_target("").is_err());
        assert!(parse_target("example.com:notaport").is_err());
        assert!(parse_target("[::1").is_err());
    }
}
