//! An explicitly separate, direct TLS connection. No proxy or HTTP credentials.
use super::{Args, TlsProbe, fingerprint};
use anyhow::{Context, Result, bail};
use reqwest::Url;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    fs,
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) fn configuration(args: &Args) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    for path in &args.cacert {
        let content =
            fs::read(path).with_context(|| format!("Cannot read CA file {}", path.display()))?;
        let mut added = false;
        for pem in x509_parser::pem::Pem::iter_from_buffer(&content) {
            let pem = pem.context("Invalid CA PEM bundle")?;
            if pem.label == "CERTIFICATE" {
                roots
                    .add(CertificateDer::from(pem.contents))
                    .context("Invalid CA certificate")?;
                added = true;
            }
        }
        if !added {
            bail!("CA file {} contains no certificates", path.display());
        }
    }
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if args.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier(provider)));
    }
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub(super) fn inspect(url: &Url, config: Arc<ClientConfig>, timeout: Duration) -> Result<TlsProbe> {
    let host = url
        .host_str()
        .context("Missing TLS hostname")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default().context("Missing TLS port")?;
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .context("TLS probe DNS lookup failed")?
        .collect();
    let deadline = Instant::now() + timeout;
    let mut socket = None;
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining.min(Duration::from_secs(5))) {
            Ok(stream) => {
                socket = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut socket = socket
        .with_context(|| format!("Cannot connect directly to {host}:{port}: {last_error:?}"))?;
    let server_name = ServerName::try_from(host.to_owned()).context("Invalid TLS server name")?;
    let mut connection = ClientConnection::new(config, server_name)?;
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("TLS probe timed out");
        }
        socket.set_read_timeout(Some(remaining))?;
        socket.set_write_timeout(Some(remaining))?;
        connection
            .complete_io(&mut socket)
            .context("TLS handshake failed")?;
    }
    let report = TlsProbe {
        connection: "separate direct TLS handshake; does not use HTTP proxy settings",
        remote_address: socket.peer_addr()?.to_string(),
        protocol: connection.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
            other => format!("{other:?}"),
        }),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite())),
        alpn: connection
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        key_exchange_group: connection
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name())),
        leaf_sha256_fingerprint: connection
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| fingerprint(c.as_ref())),
    };
    connection.send_close_notify();
    let _ = connection.write_tls(&mut socket);
    Ok(report)
}

#[derive(Debug)]
struct InsecureVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
