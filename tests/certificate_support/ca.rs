//! Local TLS ACME fixture. It verifies CSR signatures and observes the real challenge
//! listener, but deliberately does not implement public-CA policy or JWS authentication.
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, Issuer, KeyPair,
};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, ServerName, UnixTime};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct Authority {
    pub issuer: Issuer<'static, KeyPair>,
    pub pem: String,
}
impl Authority {
    pub fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let certificate = params.self_signed(&key).unwrap();
        Self {
            issuer: Issuer::new(params, key),
            pem: certificate.pem(),
        }
    }
    pub fn leaf(&self, hostname: &str, due: bool) -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![hostname.to_owned()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(if due { 85 } else { 1 });
        params.not_after = now + time::Duration::days(if due { 2 } else { 90 });
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        (format!("{}{}", certificate.pem(), self.pem), key)
    }
}

pub struct Ingress {
    pub address: SocketAddr,
    pub target: Arc<Mutex<Option<SocketAddr>>>,
    task: JoinHandle<()>,
}
impl Ingress {
    pub async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = Arc::new(Mutex::new(None::<SocketAddr>));
        let targets = target.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let (mut downstream, _) = accept.unwrap();
                        let target = *targets.lock().unwrap();
                        connections.spawn(async move {
                            if let Some(target) = target
                                && let Ok(mut upstream) = TcpStream::connect(target).await {
                                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            address,
            target,
            task,
        }
    }
}
impl Drop for Ingress {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct Order {
    authorized: bool,
    certificate: Option<String>,
}
struct State {
    base: String,
    ca: Authority,
    orders: Mutex<HashMap<usize, Order>>,
    count: AtomicUsize,
    requests: AtomicUsize,
    challenges: AtomicUsize,
    target: SocketAddr,
}
pub struct FakeCa {
    pub directory: String,
    state: Arc<State>,
    task: JoinHandle<()>,
}
impl FakeCa {
    pub async fn new(ca: Authority, target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("https://localhost:{}", address.port());
        let (pem, key) = ca.leaf("localhost", false);
        use rustls::pki_types::pem::PemObject;
        let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                certificates,
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let state = Arc::new(State {
            base: base.clone(),
            ca,
            orders: Mutex::new(HashMap::new()),
            count: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            challenges: AtomicUsize::new(0),
            target,
        });
        let server = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let (stream, _) = accept.unwrap();
                        let acceptor = acceptor.clone(); let state = server.clone();
                        connections.spawn(async move {
                            let Ok(tls) = acceptor.accept(stream).await else { return };
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service_fn(move |request| handle(state.clone(), request))).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            directory: format!("{base}/directory"),
            state,
            task,
        }
    }
    pub fn orders(&self) -> usize {
        self.state.count.load(Ordering::SeqCst)
    }
    pub fn challenges(&self) -> usize {
        self.state.challenges.load(Ordering::SeqCst)
    }
    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }
}
impl Drop for FakeCa {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    state: Arc<State>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    state.requests.fetch_add(1, Ordering::SeqCst);
    let path = request.uri().path().to_owned();
    let body = request.into_body().collect().await.unwrap().to_bytes();
    let jws: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    let payload: Value = jws
        .get("payload")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .map(|payload| serde_json::from_slice(&decode(payload)).unwrap())
        .unwrap_or_else(|| json!({}));
    let mut location = None;
    let response = if path == "/directory" {
        json!({"newNonce":format!("{}/nonce",state.base),"newAccount":format!("{}/account",state.base),"newOrder":format!("{}/orders",state.base)}).to_string()
    } else if path == "/nonce" {
        String::new()
    } else if path == "/account" {
        location = Some(format!("{}/account/1", state.base));
        json!({"status":"valid"}).to_string()
    } else if path == "/orders" {
        let id = state.count.fetch_add(1, Ordering::SeqCst) + 1;
        state.orders.lock().unwrap().insert(id, Order::default());
        // The first real newOrder remains pending until the old process is killed.
        // A finite fixture deadline bounds an abandoned remote request.
        if id == 1 {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        location = Some(format!("{}/order/{id}", state.base));
        order_json(&state, id)
    } else {
        let id: usize = path.rsplit('/').next().unwrap().parse().unwrap();
        if path.starts_with("/auth/") {
            let authorized = state.orders.lock().unwrap().get(&id).unwrap().authorized;
            json!({"status":if authorized {"valid"} else {"pending"},"identifier":{"type":"dns","value":"edge.example.test"},"challenges":[{"type":"tls-alpn-01","url":format!("{}/challenge/{id}",state.base),"token":format!("local-token-{id}"),"status":"pending"}]}).to_string()
        } else if path.starts_with("/challenge/") {
            observe_acme_challenge(state.target).await.unwrap();
            state.challenges.fetch_add(1, Ordering::SeqCst);
            state
                .orders
                .lock()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .authorized = true;
            json!({}).to_string()
        } else if path.starts_with("/finalize/") {
            let csr = CertificateSigningRequestDer::from(decode(payload["csr"].as_str().unwrap()));
            let mut csr = CertificateSigningRequestParams::from_der(&csr).unwrap();
            csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
            csr.params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);
            let certificate = csr.signed_by(&state.ca.issuer).unwrap();
            state
                .orders
                .lock()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .certificate = Some(format!("{}{}", certificate.pem(), state.ca.pem));
            order_json(&state, id)
        } else if path.starts_with("/certificate/") {
            state
                .orders
                .lock()
                .unwrap()
                .get(&id)
                .unwrap()
                .certificate
                .clone()
                .unwrap()
        } else {
            order_json(&state, id)
        }
    };
    let mut builder = Response::builder()
        .header("replay-nonce", "local-nonce")
        .header("content-type", "application/json");
    if let Some(location) = location {
        builder = builder.status(201).header("location", location);
    }
    Ok(builder.body(Full::new(Bytes::from(response))).unwrap())
}
fn order_json(state: &State, id: usize) -> String {
    let orders = state.orders.lock().unwrap();
    let order = orders.get(&id).unwrap();
    let status = if order.certificate.is_some() {
        "valid"
    } else if order.authorized {
        "ready"
    } else {
        "pending"
    };
    json!({"status":status,"authorizations":[format!("{}/auth/{id}",state.base)],"finalize":format!("{}/finalize/{id}",state.base),"certificate":format!("{}/certificate/{id}",state.base)}).to_string()
}
fn decode(value: &str) -> Vec<u8> {
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut result = Vec::new();
    for byte in value.bytes() {
        let n = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => panic!("invalid fixture base64"),
        };
        accumulator = (accumulator << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((accumulator >> bits) as u8);
        }
    }
    result
}

#[derive(Debug)]
struct ChallengeVerifier;
impl rustls::client::danger::ServerCertVerifier for ChallengeVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|_| rustls::Error::General("invalid challenge".to_owned()))?;
        let challenge = parsed.extensions().iter().any(|extension| {
            extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31"
                && extension.critical
                && extension.value.len() == 34
        });
        if !challenge {
            return Err(rustls::Error::General(
                "ordinary snapshot cannot answer a challenge".to_owned(),
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        {
            let (_, parsed) =
                x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| {
                    rustls::Error::General("invalid fixture challenge certificate".to_owned())
                })?;
            rustls::crypto::verify_tls13_signature_with_raw_key(
                message,
                &rustls::pki_types::SubjectPublicKeyInfoDer::from(parsed.public_key().raw),
                signature,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
pub async fn observe_acme_challenge(target: SocketAddr) -> io::Result<()> {
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChallengeVerifier))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let tls = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(target).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        tls.connect(ServerName::try_from("edge.example.test").unwrap(), stream),
    )
    .await
    .map_err(io::Error::other)??;
    Ok(())
}
