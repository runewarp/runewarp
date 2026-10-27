use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_acme::{AcmeConfig, EventOk};
use tokio::sync::{Notify, watch};

use super::{
    CertificateOwner, CertificateSnapshot, CertificateStore, CertificateValidation,
    ChallengeRouteObserver, ChallengeRouteRequest, TcpChallengeRoute, hex_digest,
};

/// Inputs owned by the embedding process. Default CLI operation observes the public
/// Server-hostname TCP 443 route itself. Controlled operation requests ownership only
/// when its caller has committed to takeover and supplies an external routing witness.
#[derive(Clone)]
pub struct ServerAcmeOptions {
    pub validation: CertificateValidation,
    pub directory_url: String,
    pub client_config: Arc<rustls::ClientConfig>,
    pub route_observer: Arc<dyn ChallengeRouteObserver>,
    pub recovery_timeout: Duration,
    pub retry_interval: Duration,
    pub request_ownership_on_start: bool,
    pub storage_io: Arc<dyn super::CertificateStoreIo>,
}

impl ServerAcmeOptions {
    /// Explicit controller mode. No ACME work starts until `request_ownership`.
    pub fn new(
        validation: CertificateValidation,
        directory_url: &str,
        client_config: Arc<rustls::ClientConfig>,
        route_observer: Arc<dyn ChallengeRouteObserver>,
    ) -> io::Result<Self> {
        let uri: http::Uri = directory_url.parse().map_err(io::Error::other)?;
        if uri.scheme_str() != Some("https") || uri.host().is_none() {
            return Err(io::Error::other("ACME directory requires HTTPS"));
        }
        Ok(Self {
            validation,
            directory_url: directory_url.to_owned(),
            client_config,
            route_observer,
            recovery_timeout: Duration::from_secs(300),
            retry_interval: Duration::from_secs(1),
            request_ownership_on_start: false,
            storage_io: Arc::new(super::LocalCertificateStoreIo),
        })
    }

    pub(crate) fn public(hostname: crate::ServerHostname) -> io::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_native_certs::load_native_certs().certs {
            roots.add(certificate).map_err(io::Error::other)?;
        }
        if roots.is_empty() {
            return Err(io::Error::other(
                "no Server certificate trust roots available",
            ));
        }
        let roots = Arc::new(roots);
        let validation = CertificateValidation::new(
            hostname,
            roots.clone(),
            Duration::from_secs(24 * 3600),
            Duration::from_secs(3600),
        )?;
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut options = Self::new(
            validation,
            rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            client,
            Arc::new(TcpChallengeRoute::default()),
        )?;
        options.request_ownership_on_start = true;
        Ok(options)
    }
}

/// Sanitized runtime facts. `serving` is independent of ACME ownership and driving.
#[derive(Clone, Debug)]
pub struct ServerCertificateStatus {
    pub serving: bool,
    pub owns_acme: bool,
    pub driving_acme: bool,
    pub maintenance: bool,
    pub fingerprint: Option<String>,
    pub expires_at: Option<SystemTime>,
    pub route_version: Option<String>,
    pub failure: Option<&'static str>,
}

struct State {
    snapshot: Option<CertificateSnapshot>,
    challenge: Option<Arc<dyn ResolvesServerCert>>,
    owner: bool,
    driving: bool,
    maintenance: bool,
    route_version: Option<String>,
    failure: Option<&'static str>,
    store: Option<CertificateStore>,
    recovery_started: Option<tokio::time::Instant>,
}

struct Controller {
    directory: PathBuf,
    email: String,
    options: ServerAcmeOptions,
    state: Mutex<State>,
    requested: AtomicBool,
    route_lost: AtomicBool,
    running: AtomicBool,
    notify: Notify,
    ready: watch::Sender<bool>,
}

/// Shared handle used by Server startup, TLS resolvers and the owning rollout caller.
/// It grants no rollout authority and never resumes a drained Server.
#[derive(Clone)]
pub struct ServerCertificateController {
    inner: Arc<Controller>,
}

impl ServerCertificateController {
    pub(crate) fn new(
        directory: PathBuf,
        email: String,
        options: ServerAcmeOptions,
    ) -> io::Result<Self> {
        if options.recovery_timeout.is_zero() || options.retry_interval.is_zero() {
            return Err(io::Error::other(
                "certificate recovery deadlines must be finite and positive",
            ));
        }
        let (snapshot, failure) = match CertificateStore::read_snapshot(
            &directory,
            &options.validation,
            options.validation.now(),
        ) {
            Ok(snapshot) => (snapshot, None),
            Err(_) => (None, Some("committed serving snapshot unavailable")),
        };
        let ready = snapshot.is_some();
        let requested = options.request_ownership_on_start;
        Ok(Self {
            inner: Arc::new(Controller {
                directory,
                email,
                options,
                state: Mutex::new(State {
                    snapshot,
                    challenge: None,
                    owner: false,
                    driving: false,
                    maintenance: false,
                    route_version: None,
                    failure,
                    store: None,
                    recovery_started: requested.then(tokio::time::Instant::now),
                }),
                requested: AtomicBool::new(requested),
                route_lost: AtomicBool::new(false),
                running: AtomicBool::new(false),
                notify: Notify::new(),
                ready: watch::Sender::new(ready),
            }),
        })
    }

    /// Install an authenticated owner-exported immutable snapshot. Validation is repeated
    /// against this runtime's hostname, roots and full minimum-lifetime budget.
    pub fn install_snapshot(&self, snapshot: CertificateSnapshot) -> io::Result<()> {
        let snapshot = CertificateSnapshot::validate(
            &snapshot.pem,
            &self.inner.options.validation,
            self.inner.options.validation.now(),
        )?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        if state.maintenance {
            return Err(io::Error::other("certificate maintenance is terminal"));
        }
        if state
            .snapshot
            .as_ref()
            .is_none_or(|current| current.fingerprint() != snapshot.fingerprint())
        {
            tracing::info!(server_hostname = %self.inner.options.validation.hostname, fingerprint = snapshot.fingerprint(), expires_at = ?snapshot.expires_at(), "Server serving certificate validated");
        }
        state.snapshot = Some(snapshot);
        self.inner.ready.send_replace(true);
        Ok(())
    }

    /// Begin bounded takeover. The stable process lock, then a fresh consumed-route
    /// observation, still gate every ACME request. The caller owns irreversible-drain policy.
    pub fn request_ownership(&self) {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("certificate controller mutex poisoned");
            if !state.driving && state.recovery_started.is_none() {
                state.recovery_started = Some(tokio::time::Instant::now());
            }
        }
        self.inner.requested.store(true, Ordering::SeqCst);
        self.inner.notify.notify_one();
    }

    /// Revoke routing evidence immediately. Ordinary snapshot serving continues during
    /// bounded recovery; ACME polling and challenge ownership require a fresh observation.
    pub fn challenge_route_lost(&self) {
        self.inner.route_lost.store(true, Ordering::SeqCst);
        let mut state = self
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        state.challenge = None;
        state.driving = false;
        state.route_version = None;
        state
            .recovery_started
            .get_or_insert_with(tokio::time::Instant::now);
        self.inner.notify.notify_one();
    }

    /// The pre-drain gate. Failure leaves the running Server and its last-good serving
    /// certificate untouched. This does not promise completion of an in-flight renewal.
    pub fn export_snapshot(&self, required_remaining: Duration) -> io::Result<CertificateSnapshot> {
        let store = self
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned")
            .store
            .clone()
            .ok_or_else(|| io::Error::other("no durable owner snapshot available"))?;
        store.export_snapshot(required_remaining)
    }

    pub fn status(&self) -> ServerCertificateStatus {
        let state = self
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        ServerCertificateStatus {
            serving: usable(&state, &self.inner.options.validation),
            owns_acme: state.owner,
            driving_acme: state.driving,
            maintenance: state.maintenance,
            fingerprint: state.snapshot.as_ref().map(|s| s.fingerprint.clone()),
            expires_at: state.snapshot.as_ref().map(|s| s.expires_at),
            route_version: state.route_version.clone(),
            failure: state.failure,
        }
    }

    pub(crate) fn readiness(&self) -> watch::Receiver<bool> {
        self.inner.ready.subscribe()
    }
    pub(crate) fn serving_resolver(&self) -> Arc<dyn ResolvesServerCert> {
        Arc::new(Resolver {
            controller: self.clone(),
            challenge: false,
        })
    }
    pub(crate) fn challenge_config(&self) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver {
                controller: self.clone(),
                challenge: true,
            }));
        config.alpn_protocols = vec![crate::acme::ACME_TLS_ALPN.to_vec()];
        Arc::new(config)
    }

    pub(crate) async fn run(&self) -> io::Result<()> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Err(io::Error::other("certificate controller already running"));
        }
        let _running = Running(self.clone());
        let drive = self.drive();
        tokio::pin!(drive);
        loop {
            tokio::select! {
                result = &mut drive => return result,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    let status = self.status();
                    self.inner.ready.send_replace(status.serving);
                    if status.expires_at.is_some() && !status.serving { return self.maintenance("certificate safety deadline reached"); }
                    let overdue = self.inner.state.lock().expect("certificate controller mutex poisoned").recovery_started.is_some_and(|started| started.elapsed() >= self.inner.options.recovery_timeout);
                    if overdue { return self.maintenance("certificate takeover recovery deadline reached"); }
                }
            }
        }
    }

    async fn drive(&self) -> io::Result<()> {
        let mut owner = None;
        loop {
            if !self.inner.requested.load(Ordering::SeqCst) {
                self.inner.notify.notified().await;
                continue;
            }
            let _result = self.activate(&mut owner).await;
            {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .expect("certificate controller mutex poisoned");
                state.challenge = None;
                state.driving = false;
                state.store = None;
                state.route_version = None;
                if state.failure.is_none() {
                    state.failure = Some("certificate activation failed");
                }
                state
                    .recovery_started
                    .get_or_insert_with(tokio::time::Instant::now);
            }
            tokio::time::sleep(self.inner.options.retry_interval).await;
        }
    }

    async fn activate(&self, owner: &mut Option<CertificateOwner>) -> io::Result<()> {
        if owner.is_none() {
            let directory = self.inner.directory.clone();
            *owner = tokio::task::spawn_blocking(move || CertificateOwner::try_acquire(&directory))
                .await
                .map_err(io::Error::other)??;
            if owner.is_none() {
                self.failure("certificate owner is still running");
                return Err(io::Error::other("certificate owner is still running"));
            }
            self.inner
                .state
                .lock()
                .expect("certificate controller mutex poisoned")
                .owner = true;
            tracing::info!(server_hostname = %self.inner.options.validation.hostname, "Server certificate ownership acquired");
        }
        let owner = owner.as_ref().expect("owner was acquired").clone();
        let policy = self.inner.options.validation.clone();
        let contact = format!("mailto:{}", self.inner.email);
        let url = self.inner.options.directory_url.clone();
        let storage_io = self.inner.options.storage_io.clone();
        let store = tokio::task::spawn_blocking(move || {
            CertificateStore::open_with_io(owner, policy, &contact, &url, storage_io)
        })
        .await
        .map_err(io::Error::other)?
        .map_err(|_| {
            self.failure("certificate storage unavailable");
            io::Error::other("certificate storage unavailable")
        })?;
        // Sequential migration only. The lock is already held; passive runtimes never
        // inspect legacy files. Old binaries must be stopped before this owner starts.
        store.import_legacy().await?;
        if let Ok(snapshot) = self.durable_snapshot(store.clone()).await {
            self.install_snapshot(snapshot)?;
        }
        self.inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned")
            .store = Some(store.clone());
        let (request, proof) = route_proof(self.inner.options.validation.hostname.clone())?;
        self.inner.route_lost.store(false, Ordering::SeqCst);
        self.inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned")
            .challenge = Some(Arc::new(proof));
        let observation = self
            .inner
            .options
            .route_observer
            .observe(request.clone())
            .await
            .map_err(|_| {
                self.failure("challenge route not consumed");
                io::Error::other("challenge route not consumed")
            })?;
        super::route::validate_version(&observation.version)?;
        if observation.fingerprint != request.fingerprint
            || self.inner.route_lost.load(Ordering::SeqCst)
        {
            return Err(io::Error::other("stale challenge route observation"));
        }
        let mut acme = AcmeConfig::new_with_client_config(
            [self.inner.options.validation.hostname.as_str()],
            self.inner.options.client_config.clone(),
        )
        .contact_push(format!("mailto:{}", self.inner.email))
        .directory(&self.inner.options.directory_url)
        .cache(store.clone())
        .state();
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("certificate controller mutex poisoned");
            state.challenge = Some(acme.resolver());
            state.driving = true;
            state.route_version = Some(observation.version);
            state.failure = None;
        }
        loop {
            if self.inner.route_lost.load(Ordering::SeqCst) {
                return Err(io::Error::other("challenge route lost"));
            }
            let event = tokio::select! {
                biased;
                _ = self.inner.notify.notified() => {
                    if self.inner.route_lost.load(Ordering::SeqCst) { return Err(io::Error::other("challenge route lost")); }
                    continue;
                }
                event = acme.next() => event,
            };
            match event {
                Some(Ok(EventOk::DeployedCachedCert | EventOk::CertCacheStore)) => {
                    let snapshot = self.durable_snapshot(store.clone()).await?;
                    self.install_snapshot(snapshot)?;
                    self.inner
                        .state
                        .lock()
                        .expect("certificate controller mutex poisoned")
                        .recovery_started = None;
                    // Having a usable durable active certificate ends recovery. Subsequent
                    // ACME errors begin a new bounded attempt in the outer driver.
                    return self.drive_active(acme, store).await;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    self.failure("ACME acquisition or persistence failed");
                    return Err(io::Error::other("ACME acquisition or persistence failed"));
                }
            }
        }
    }

    async fn durable_snapshot(&self, store: CertificateStore) -> io::Result<CertificateSnapshot> {
        let minimum = self.inner.options.validation.minimum_remaining;
        tokio::task::spawn_blocking(move || store.export_snapshot(minimum))
            .await
            .map_err(io::Error::other)?
    }

    async fn drive_active(
        &self,
        mut acme: rustls_acme::AcmeState<io::Error>,
        store: CertificateStore,
    ) -> io::Result<()> {
        // The independent watchdog still enforces certificate safety. Recovery timeout is
        // applied only after this active loop returns an error, not to ordinary renewal sleep.
        loop {
            if self.inner.route_lost.load(Ordering::SeqCst) {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = self.inner.notify.notified() => if self.inner.route_lost.load(Ordering::SeqCst) { return Ok(()); },
                event = acme.next() => match event {
                    Some(Ok(EventOk::CertCacheStore)) => self.install_snapshot(self.durable_snapshot(store.clone()).await?)?,
                    Some(Ok(_)) => {},
                    Some(Err(_)) | None => { self.failure("ACME renewal or persistence failed"); return Ok(()); }
                },
            }
        }
    }

    fn failure(&self, reason: &'static str) {
        self.inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned")
            .failure = Some(reason);
    }
    fn maintenance(&self, reason: &'static str) -> io::Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        state.maintenance = true;
        state.challenge = None;
        state.driving = false;
        state.failure = Some(reason);
        tracing::warn!(server_hostname = %self.inner.options.validation.hostname, reason, "Server certificate maintenance started");
        self.inner.ready.send_replace(false);
        Err(io::Error::other(reason))
    }
}

struct Running(ServerCertificateController);
impl Drop for Running {
    fn drop(&mut self) {
        let mut state = self
            .0
            .inner
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        state.challenge = None;
        state.driving = false;
    }
}

fn usable(state: &State, policy: &CertificateValidation) -> bool {
    let now = policy.now();
    !state.maintenance
        && state.snapshot.as_ref().is_some_and(|s| {
            now >= s.valid_from
                && s.expires_at
                    .duration_since(now)
                    .is_ok_and(|remaining| remaining > policy.safety_margin)
        })
}

struct Resolver {
    controller: ServerCertificateController,
    challenge: bool,
}
impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCertificateResolver")
            .field("challenge", &self.challenge)
            .finish()
    }
}
impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let controller = &self.controller.inner;
        if hello.server_name() != Some(controller.options.validation.hostname.as_str()) {
            return None;
        }
        let state = controller
            .state
            .lock()
            .expect("certificate controller mutex poisoned");
        if self.challenge {
            if !rustls_acme::is_tls_alpn_challenge(&hello) || !state.owner || state.maintenance {
                return None;
            }
            state.challenge.as_ref()?.resolve(hello)
        } else {
            if hello
                .alpn()
                .is_some_and(|mut protocols| protocols.any(|p| p == crate::acme::ACME_TLS_ALPN))
                || !usable(&state, &controller.options.validation)
            {
                return None;
            }
            state.snapshot.as_ref().map(|s| s.key.clone())
        }
    }
}

#[derive(Debug)]
struct Proof(Arc<CertifiedKey>);
impl ResolvesServerCert for Proof {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn route_proof(hostname: crate::ServerHostname) -> io::Result<(ChallengeRouteRequest, Proof)> {
    let generated = rcgen::generate_simple_self_signed(vec![hostname.as_str().to_owned()])
        .map_err(io::Error::other)?;
    let certificate = generated.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .map_err(io::Error::other)?;
    let key = CertifiedKey::from_der(
        vec![certificate.clone()],
        key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(io::Error::other)?;
    let fingerprint = hex_digest(certificate.as_ref());
    Ok((
        ChallengeRouteRequest {
            hostname,
            certificate,
            fingerprint,
        },
        Proof(Arc::new(key)),
    ))
}
