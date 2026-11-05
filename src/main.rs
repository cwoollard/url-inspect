use std::{
    collections::HashSet,
    fs,
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{CommandFactory, Parser, ValueEnum};
use reqwest::{
    Url,
    blocking::Client,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION},
    redirect::Policy,
    tls::TlsInfo,
};
use scraper::{Html, Selector};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const BODY_LIMIT: u64 = 2 * 1024 * 1024;
mod tls_probe;

#[derive(Debug, Parser)]
#[command(
    version,
    about,
    after_help = "Examples:\n  url-inspect https://example.com --csp\n  url-inspect https://example.com --headers --tls\n  url-inspect https://example.com --cert\n  url-inspect https://example.com --csp --cert --json\n  url-inspect https://example.local --csp --cacert company-ca.pem\n\nWithout an inspection switch, displays help without making a request.\nInspects HTTP responses; does not execute JavaScript or generate a policy."
)]
struct Args {
    /// URL to inspect (defaults to HTTPS when no scheme is supplied)
    url: Option<String>,
    /// Show enforced and report-only Content Security Policies
    #[arg(long)]
    csp: bool,
    /// Show all HTTP response headers, including repeated fields
    #[arg(long = "headers")]
    response_headers: bool,
    /// Probe TLS version, negotiated cipher and ALPN using a separate direct connection
    #[arg(long)]
    tls: bool,
    /// Show the TLS leaf certificate, including SANs, dates and fingerprint
    #[arg(short = 'c', long)]
    cert: bool,
    /// Include the leaf certificate in PEM format (implies --cert)
    #[arg(long)]
    cert_pem: bool,
    /// Emit a structured JSON report
    #[arg(short = 'j', long)]
    json: bool,
    /// Terminal colour output (JSON is always uncoloured; auto respects NO_COLOR)
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,
    /// Inspect only the first response
    #[arg(long)]
    no_follow: bool,
    /// Maximum number of redirects
    #[arg(long, default_value_t = 10)]
    max_redirects: usize,
    /// Request timeout in seconds, per redirect hop
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    /// Additional trusted CA certificates in PEM format; repeatable
    #[arg(long, value_name = "FILE")]
    cacert: Vec<PathBuf>,
    /// Request header; repeatable. Never forwarded after a cross-origin redirect
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
    /// Disable TLS verification for diagnostics; explicitly marked in output
    #[arg(short = 'k', long)]
    insecure: bool,
    /// Disable environment proxy settings
    #[arg(long)]
    no_proxy: bool,
    /// Skip reading HTML for CSP meta tags
    #[arg(long)]
    headers_only: bool,
    /// Exit 2 if the final response has no enforced policy (implies --csp)
    #[arg(long)]
    require_csp: bool,
}

impl Args {
    fn show_csp(&self) -> bool {
        self.csp || self.require_csp
    }
    fn has_mode(&self) -> bool {
        self.show_csp() || self.cert || self.cert_pem || self.response_headers || self.tls
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

fn colour_enabled(mode: ColorMode, terminal: bool, no_color: bool) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => terminal && !no_color,
    }
}

fn paint(text: &str, code: &str, colour: bool) -> String {
    if colour {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

// Fixed-duration display units: a month is 30 days, a year is 365 days.
// Show every nonzero unit down to minutes; show seconds only below a minute.
fn expiry_duration(seconds: i64) -> String {
    if seconds == 0 {
        return "expires now".into();
    }
    let mut remaining = seconds.unsigned_abs();
    let mut parts = Vec::new();
    for (unit, size) in [
        ("year", 365 * 86400),
        ("month", 30 * 86400),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ] {
        let count = remaining / size;
        remaining %= size;
        if count > 0 {
            parts.push(format!(
                "{count} {unit}{}",
                if count == 1 { "" } else { "s" }
            ));
        }
        if unit == "minute" && !parts.is_empty() {
            break;
        }
    }
    let duration = parts.join(", ");
    if seconds < 0 {
        format!("expired {duration} ago")
    } else {
        duration
    }
}

#[derive(Debug, Serialize)]
struct Csp {
    source: &'static str,
    report_only: bool,
    value: String,
    bytes: usize,
}

impl Csp {
    fn new(source: &'static str, report_only: bool, value: String) -> Self {
        let bytes = value.len();
        Self {
            source,
            report_only,
            value,
            bytes,
        }
    }
}

#[derive(Debug, Serialize)]
struct Certificate {
    subject: String,
    issuer: String,
    serial: String,
    subject_alternative_names: Vec<String>,
    not_before: String,
    not_after: String,
    valid_now: bool,
    seconds_until_expiry: i64,
    expiry: String,
    sha256_fingerprint: String,
    signature_algorithm_oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pem: Option<String>,
}

#[derive(Debug, Serialize)]
struct Hop {
    url: String,
    status: u16,
    location: Option<String>,
    http_version: String,
    remote_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_headers: Option<Vec<ResponseHeader>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_probe: Option<TlsProbe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policies: Option<Vec<Csp>>,
    certificate: Option<Certificate>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResponseHeader {
    name: String,
    value: String,
}

fn response_headers(headers: &HeaderMap) -> Vec<ResponseHeader> {
    headers
        .iter()
        .map(|(name, value)| ResponseHeader {
            name: name.to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct TlsProbe {
    connection: &'static str,
    remote_address: String,
    protocol: Option<String>,
    cipher_suite: Option<String>,
    alpn: Option<String>,
    key_exchange_group: Option<String>,
    leaf_sha256_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    tls_verification_enabled: bool,
    hops: Vec<Hop>,
}

fn parse_url(input: &str) -> Result<Url> {
    let candidate = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&candidate).context("Invalid URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("Only HTTP and HTTPS URLs with a hostname are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Credentials in URLs are not supported; use --header instead");
    }
    url.set_fragment(None);
    Ok(url)
}

fn request_headers(args: &Args) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for item in &args.headers {
        let (name, value) = item
            .split_once(':')
            .context("Headers must use NAME: VALUE format")?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).context("Invalid header name")?;
        if name == reqwest::header::HOST {
            bail!("Use the URL hostname rather than overriding Host");
        }
        let mut value = HeaderValue::from_str(value.trim()).context("Invalid header value")?;
        value.set_sensitive(true);
        headers.append(name, value);
    }
    Ok(headers)
}

fn certificate(der: &[u8], include_pem: bool) -> Result<Certificate> {
    let (_, cert) = parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("Cannot parse certificate: {e}"))?;
    let mut names = Vec::new();
    if let Some(san) = cert
        .subject_alternative_name()
        .context("Invalid SAN extension")?
    {
        for name in &san.value.general_names {
            names.push(match name {
                GeneralName::DNSName(value) => value.to_string(),
                GeneralName::IPAddress(value) => match value.len() {
                    4 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*value)?).to_string(),
                    16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*value)?).to_string(),
                    _ => format!("IP:{value:?}"),
                },
                other => format!("{other:?}"),
            });
        }
    }
    let pem = include_pem.then(|| {
        let encoded = STANDARD.encode(der);
        let lines = encoded
            .as_bytes()
            .chunks(64)
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n")
    });
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    Ok(Certificate {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        subject_alternative_names: names,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        valid_now: cert.validity().is_valid(),
        seconds_until_expiry: cert.validity().not_after.timestamp() - now,
        expiry: expiry_duration(cert.validity().not_after.timestamp() - now),
        sha256_fingerprint: fingerprint(der),
        signature_algorithm_oid: cert.signature_algorithm.algorithm.to_id_string(),
        pem,
    })
}

fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn meta_policies(html: &str) -> Vec<Csp> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("head meta[http-equiv][content]").unwrap();
    document
        .select(&selector)
        .filter_map(|element| {
            let kind = element.value().attr("http-equiv")?;
            if !kind.eq_ignore_ascii_case("Content-Security-Policy") {
                return None;
            }
            Some(Csp::new(
                "meta",
                false,
                element.value().attr("content")?.to_owned(),
            ))
        })
        .collect()
}

fn inspect(args: &Args) -> Result<Report> {
    let mut url = parse_url(args.url.as_deref().context("A URL is required")?)?;
    let headers = request_headers(args)?;
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(args.timeout))
        .connect_timeout(Duration::from_secs(args.timeout.min(10)))
        .user_agent(concat!("url-inspect/", env!("CARGO_PKG_VERSION")))
        .tls_info(true)
        .danger_accept_invalid_certs(args.insecure);
    // Automatic decompression removes Content-Encoding and Content-Length.
    // Header inspection requests identity encoding and preserves what was received.
    if args.response_headers {
        builder = builder.gzip(false).brotli(false).deflate(false);
    }
    if args.no_proxy {
        builder = builder.no_proxy();
    }
    for path in &args.cacert {
        let pem =
            fs::read(path).with_context(|| format!("Cannot read CA file {}", path.display()))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem).context("Invalid CA PEM bundle")? {
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build().context("Cannot configure HTTP client")?;
    let tls_config = args
        .tls
        .then(|| tls_probe::configuration(args))
        .transpose()?;
    let mut report = Report {
        tls_verification_enabled: !args.insecure,
        hops: Vec::new(),
    };
    let mut visited = HashSet::new();
    let mut forward_headers = true;
    loop {
        if !visited.insert(url.to_string()) {
            bail!("Redirect loop detected at {url}");
        }
        let mut request = client.get(url.clone());
        if args.response_headers {
            request = request.header(reqwest::header::ACCEPT_ENCODING, "identity");
        }
        if forward_headers {
            request = request.headers(headers.clone());
        }
        let response = request
            .send()
            .with_context(|| format!("GET {url} failed"))?;
        let status = response.status();
        let http_version = format!("{:?}", response.version());
        let remote_address = response.remote_addr().map(|address| address.to_string());
        let visible_headers = args
            .response_headers
            .then(|| response_headers(response.headers()));
        let mut policies = Vec::new();
        for (name, report_only) in [
            ("content-security-policy", false),
            ("content-security-policy-report-only", true),
        ] {
            for value in response
                .headers()
                .get_all(name)
                .iter()
                .filter(|_| args.show_csp())
            {
                policies.push(Csp::new(
                    "header",
                    report_only,
                    value
                        .to_str()
                        .context("CSP header is not valid text")?
                        .to_owned(),
                ));
            }
        }
        let location = response
            .headers()
            .get(LOCATION)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .context("Invalid redirect Location")?;
        let mut warnings = Vec::new();
        if (args.cert || args.cert_pem || args.tls) && url.scheme() == "http" {
            warnings.push(
                "HTTP has no TLS certificate; use an HTTPS URL for certificate inspection".into(),
            );
        }
        if !status.is_success() {
            warnings.push(format!(
                "HTTP {status}; this may be an error or redirect page, not the intended application"
            ));
        }
        let probe = if let Some(config) = &tls_config {
            if url.scheme() == "https" {
                match tls_probe::inspect(&url, config.clone(), Duration::from_secs(args.timeout)) {
                    Ok(probe) => {
                        if let Some(der) = response
                            .extensions()
                            .get::<TlsInfo>()
                            .and_then(TlsInfo::peer_certificate)
                            && probe.leaf_sha256_fingerprint.as_deref() != Some(&fingerprint(der))
                        {
                            warnings.push("Direct TLS probe and HTTP request received different certificates; a proxy or load balancer may explain the difference".into());
                        }
                        Some(probe)
                    }
                    Err(error) => {
                        warnings.push(format!("Direct TLS probe failed: {error:#}"));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        let cert = if (args.cert || args.cert_pem) && url.scheme() == "https" {
            match response
                .extensions()
                .get::<TlsInfo>()
                .and_then(TlsInfo::peer_certificate)
            {
                Some(der) => Some(certificate(der, args.cert_pem)?),
                None => {
                    warnings.push("TLS backend did not expose a leaf certificate".into());
                    None
                }
            }
        } else {
            None
        };
        let is_html = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/html")
            });
        let encoded_body = args.response_headers
            && response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"));
        if args.show_csp() && is_html && !args.headers_only && encoded_body {
            warnings.push("Server returned an encoded body despite identity encoding; HTML meta scan skipped to preserve response headers".into());
        }
        if args.show_csp() && is_html && !args.headers_only && !encoded_body {
            let mut body = Vec::new();
            response
                .take(BODY_LIMIT + 1)
                .read_to_end(&mut body)
                .context("Cannot read HTML body")?;
            if body.len() > BODY_LIMIT as usize {
                body.truncate(BODY_LIMIT as usize);
                warnings.push(
                    "HTML meta scan truncated at 2 MiB; later meta tags may be missing".into(),
                );
            }
            policies.extend(meta_policies(&String::from_utf8_lossy(&body)));
        }
        if policies.iter().filter(|p| !p.report_only).count() > 1 {
            warnings.push("Multiple enforced policies: each must permit a resource; their allowlists are not merged".into());
        }
        report.hops.push(Hop {
            url: url.to_string(),
            status: status.as_u16(),
            location: location.clone(),
            http_version,
            remote_address,
            response_headers: visible_headers,
            tls_probe: probe,
            policies: args.show_csp().then_some(policies),
            certificate: cert,
            warnings,
        });
        if args.no_follow || !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            break;
        }
        let Some(location) = location else {
            break;
        };
        if report.hops.len() > args.max_redirects {
            bail!("Exceeded {} redirects", args.max_redirects);
        }
        let next = parse_url(
            url.join(&location)
                .context("Invalid redirect URL")?
                .as_str(),
        )?;
        if url.scheme() == "https" && next.scheme() == "http" {
            bail!("Refusing HTTPS-to-HTTP redirect to {next}");
        }
        if url.origin() != next.origin() {
            forward_headers = false;
        }
        url = next;
    }
    Ok(report)
}

fn write_report(report: &Report, json: bool, colour: bool, mut out: impl Write) -> Result<()> {
    if json {
        serde_json::to_writer_pretty(&mut out, report)?;
        writeln!(out)?;
        return Ok(());
    }
    if !report.tls_verification_enabled {
        writeln!(
            out,
            "{}\n",
            paint(
                "WARNING: TLS certificate verification DISABLED (--insecure)",
                "1;31",
                colour
            )
        )?;
    }
    for (i, hop) in report.hops.iter().enumerate() {
        writeln!(
            out,
            "{}",
            paint(&format!("[{}] {}", i + 1, hop.url), "1;36", colour)
        )?;
        let status_colour = match hop.status {
            200..=299 => "32",
            300..=399 => "33",
            _ => "31",
        };
        writeln!(
            out,
            "{}",
            paint(
                &format!("{} {}", hop.http_version, hop.status),
                status_colour,
                colour
            )
        )?;
        if let Some(address) = &hop.remote_address {
            writeln!(out, "Remote address: {address}")?;
        }
        if let Some(location) = &hop.location {
            writeln!(out, "Location: {location}")?;
        }
        if let Some(headers) = &hop.response_headers {
            writeln!(out, "\n{}", paint("HTTP response headers:", "1;36", colour))?;
            for header in headers {
                writeln!(
                    out,
                    "  {}: {}",
                    paint(&header.name, "36", colour),
                    header.value
                )?;
            }
        }
        if let Some(tls) = &hop.tls_probe {
            writeln!(
                out,
                "\n{}",
                paint("TLS probe (separate direct connection):", "1;36", colour)
            )?;
            writeln!(
                out,
                "  Remote address: {}\n  Version: {}\n  Negotiated cipher: {}\n  ALPN: {}\n  Key-exchange group: {}",
                tls.remote_address,
                tls.protocol.as_deref().unwrap_or("unknown"),
                tls.cipher_suite.as_deref().unwrap_or("unknown"),
                tls.alpn.as_deref().unwrap_or("not negotiated"),
                tls.key_exchange_group.as_deref().unwrap_or("unknown")
            )?;
        }
        if let Some(policies) = &hop.policies {
            if policies.is_empty() {
                writeln!(out, "{}", paint("No CSP found.", "33", colour))?;
            }
            for policy in policies {
                let heading = format!(
                    "{} CSP ({}, {} bytes):",
                    if policy.report_only {
                        "Report-only"
                    } else {
                        "Enforced"
                    },
                    policy.source,
                    policy.bytes
                );
                writeln!(
                    out,
                    "\n{}",
                    paint(
                        &heading,
                        if policy.report_only { "1;33" } else { "1;32" },
                        colour
                    )
                )?;
                for directive in policy
                    .value
                    .split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let (name, values) = directive
                        .split_once(char::is_whitespace)
                        .unwrap_or((directive, ""));
                    writeln!(
                        out,
                        "  {}{}{};",
                        paint(name, "36", colour),
                        if values.is_empty() { "" } else { " " },
                        values
                    )?;
                }
            }
        }
        if let Some(cert) = &hop.certificate {
            writeln!(out, "\n{}", paint("TLS leaf certificate:", "1;36", colour))?;
            writeln!(
                out,
                "  Subject: {}\n  Issuer: {}\n  Serial: {}\n  SANs: {}\n  Not before: {}\n  Not after: {}",
                cert.subject,
                cert.issuer,
                cert.serial,
                cert.subject_alternative_names.join(", "),
                cert.not_before,
                cert.not_after
            )?;
            writeln!(
                out,
                "  Within validity dates: {}",
                paint(
                    &cert.valid_now.to_string(),
                    if cert.valid_now { "32" } else { "31" },
                    colour
                )
            )?;
            let expiry_colour = if cert.seconds_until_expiry <= 0 {
                "31"
            } else if cert.seconds_until_expiry < 30 * 86400 {
                "33"
            } else {
                "32"
            };
            writeln!(
                out,
                "  Expiry: {}\n  SHA-256: {}\n  Signature algorithm OID: {}",
                paint(&cert.expiry, expiry_colour, colour),
                cert.sha256_fingerprint,
                cert.signature_algorithm_oid
            )?;
            if let Some(pem) = &cert.pem {
                write!(out, "{pem}")?;
            }
        }
        for warning in &hop.warnings {
            writeln!(
                out,
                "{}",
                paint(&format!("Warning: {warning}"), "33", colour)
            )?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn run(args: &Args) -> Result<ExitCode> {
    let report = inspect(args)?;
    let colour = colour_enabled(
        args.color,
        io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
    );
    write_report(&report, args.json, colour, io::stdout().lock())?;
    let missing = !report.hops.last().is_some_and(|hop| {
        hop.policies
            .as_ref()
            .is_some_and(|policies| policies.iter().any(|p| !p.report_only))
    });
    Ok(if args.require_csp && missing {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    let args = Args::parse();
    if !args.has_mode() {
        if let Err(error) = Args::command().print_long_help() {
            eprintln!("Error: {error}");
            return ExitCode::FAILURE;
        }
        println!();
        return ExitCode::SUCCESS;
    }
    if args.url.is_none() {
        Args::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "A URL is required with --csp, --headers, --tls, --cert or --cert-pem",
            )
            .exit();
    }
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_readable_and_handles_expired_certificates() {
        assert_eq!(
            expiry_duration(2961998),
            "1 month, 4 days, 6 hours, 46 minutes"
        );
        assert_eq!(expiry_duration(3661), "1 hour, 1 minute");
        assert_eq!(
            expiry_duration(-90061),
            "expired 1 day, 1 hour, 1 minute ago"
        );
        assert_eq!(expiry_duration(0), "expires now");
        assert_eq!(expiry_duration(1), "1 second");
        assert_eq!(expiry_duration(60), "1 minute");
        assert_eq!(expiry_duration(30 * 86400 + 60), "1 month, 1 minute");
        assert_eq!(expiry_duration(-60), "expired 1 minute ago");
        assert_eq!(expiry_duration(365 * 86400), "1 year");
        assert!(expiry_duration(i64::MIN).starts_with("expired "));
    }

    #[test]
    fn colour_auto_obeys_terminal_and_no_color() {
        assert!(colour_enabled(ColorMode::Auto, true, false));
        assert!(!colour_enabled(ColorMode::Auto, false, false));
        assert!(!colour_enabled(ColorMode::Auto, true, true));
        assert!(!colour_enabled(ColorMode::Never, true, false));
        assert!(colour_enabled(ColorMode::Always, false, true));
    }

    #[test]
    fn json_never_contains_terminal_colours() {
        let report = Report {
            tls_verification_enabled: false,
            hops: vec![],
        };
        let mut output = Vec::new();
        write_report(&report, true, true, &mut output).unwrap();
        assert!(!output.contains(&0x1b));
        serde_json::from_slice::<serde_json::Value>(&output).unwrap();
    }

    #[test]
    fn url_defaults_to_https_and_removes_fragment() {
        assert_eq!(
            parse_url("example.com/path?q=1#section").unwrap().as_str(),
            "https://example.com/path?q=1"
        );
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("https://user:password@example.com").is_err());
    }

    #[test]
    fn meta_scan_handles_case_entities_and_multiple_policies() {
        let policies = meta_policies(
            r#"<html><head>
            <meta content="default-src &apos;self&apos;" http-equiv="CONTENT-SECURITY-POLICY">
            <meta http-equiv="Content-Security-Policy" content="frame-src https://*.example.com">
            <meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'none'">
            </head><body><meta http-equiv="Content-Security-Policy" content="ignored"></body></html>"#,
        );
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].value, "default-src 'self'");
        assert!(
            policies
                .iter()
                .all(|p| p.source == "meta" && !p.report_only)
        );
    }

    #[test]
    fn policy_size_counts_utf8_bytes() {
        let policy = Csp::new("header", false, "report-uri /é".into());
        assert_eq!(policy.bytes, 14);
    }

    #[test]
    fn request_header_validation_rejects_injection_and_host_override() {
        let args = Args::try_parse_from([
            "url-inspect",
            "example.com",
            "-H",
            "X-Test: x\r\nInjected: true",
        ])
        .unwrap();
        assert!(request_headers(&args).is_err());
        let args =
            Args::try_parse_from(["url-inspect", "example.com", "-H", "Host: example.local"])
                .unwrap();
        assert!(request_headers(&args).is_err());
    }
}
