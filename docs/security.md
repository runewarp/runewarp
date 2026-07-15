# Security

In the default passthrough mode, Runewarp does not terminate customer TLS on the public server. The server sees only the metadata it needs to authorize hostnames and forward traffic. When a service opts into terminate mode, the client terminates TLS and the local backend receives plaintext.

## What the Server can and cannot see

| Visible to the Server | Not visible to the Server |
| --- | --- |
| **Public hostname** from SNI | HTTP headers and bodies |
| Visitor source IP and port | Application plaintext |
| Connection timing and byte counts | Local backend TLS private keys |
| Authenticated **Client identity** | Decrypted customer traffic |

## Security boundaries

| Boundary | What it protects |
| --- | --- |
| Server-side **Public hostname** authorization | Prevents random public traffic from entering a Tunnel just because some Client is connected |
| Server certificate validation | Confirms the Client is connected to the intended **Server hostname** |
| **Exclusive CA trust** | Limits trust for the Tunnel connection to the configured CA bundle |
| **Control trust** | Limits trust for the Control endpoint to system roots or an exclusive CA bundle |
| Pinned **Client identity** | Confirms the Client public key authorized for the selected Tunnel |
| Backend TLS termination (passthrough) | Keeps customer TLS termination off the public edge in the default mode |
| **Public hostname CA** (terminate) | Operator-managed trust anchor for Visitors when the Client terminates TLS |

## Diagnostics visibility

Runtime diagnostics follow the same boundary.

**May be logged**

- normalized **Public hostname**
- routing outcome, connection timing, and transport errors
- effective Client `server-address` values plus resolved socket addresses on connection-attempt lines
- rejected or authenticated **Client identity** values on tunnel-auth warnings
- Client `backend-address` values in routing diagnostics
- graceful-shutdown lifecycle lines
- Managed-session role and reconnect outcome
- `server acme challenge handled` with `server-hostname=...` for `acme-tls/1` traffic on the **Server hostname**
- distinct Client ACME challenge-handling lines for terminating **Public hostnames**

**Must not be logged**

- buffered ClientHello bytes
- HTTP headers or bodies
- decrypted application plaintext
- Control snapshot input and opaque revision values
- remote socket addresses for Server tunnel lifecycle or forwarded-route events

## Public traffic invariants

- customer TLS is never terminated on the **Server**
- the Server reads only enough of the ClientHello to route
- the Server requires the complete initial ClientHello within 5 seconds and 16 KB
- pre-routing admission is bounded to 4,096 Visitors globally and 256 per accepted socket peer IP; the Server never trusts a forwarded header as source identity
- the Server routes only **Public hostnames** explicitly authorized on the matched **Tunnel**
- public traffic must be TLS
- non-TLS traffic and TLS without SNI are dropped
- **Local backends** must terminate TLS when `tls-mode = "passthrough"` (default)
- the **Client** terminates TLS when `tls-mode = "terminate"`; the Local backend receives plaintext

## Admission and overload protection

The Server and Client apply fixed admission and setup-deadline policies across their distinct public and authenticated trust boundaries:

- Visitor pre-routing capacity is acquired before spawning a handler and released immediately after ClientHello completion, rejection, error, timeout, cancellation, or shutdown. Existing routed Visitor streams do not retain this capacity.
- The public limits are 4,096 concurrent pre-routing Visitors globally and 256 per accepted peer IP. A normal load balancer may collapse many Visitors into one source bucket; Core deliberately accepts that conservative behavior rather than trusting an unverified forwarded header.
- QUIC handshake capacity is acquired before spawning handshake work and is limited to 256 concurrent handshakes.
- After routing, pending `open_bi()` opens are limited to 1,024 with a 5-second deadline, and active routed Visitor streams are limited to 4,096. Active streams are tracked in a keyed map so selective Authorization revocation can target Public hostname, Tunnel connection, or Client identity without linear identity-by-identity accumulation for ordinary cleanup.
- Authenticated active Tunnel connections are limited to 4,096 globally, 256 per Tunnel, and 64 per Client identity.
- Each Client instance enforces one aggregate stream-handler budget of 1,024 across all live Tunnel connections. Per-connection QUIC bidirectional stream credit is capped at that same 1,024 so one connection cannot advertise more than the instance can service; when multiple connections share the budget, the Client-instance semaphore remains authoritative and excess accepted streams are reset without spawning handlers. Tunneled ClientHello completion, backend connect, initial backend write, Terminate-mode handshake, and ACME challenge handshake each have a 5-second setup deadline. Successfully established proxies remain long-lived; this policy does not add a proxy lifetime or idle timeout.
- Saturation always rejects the newest work. It never evicts an existing healthy Tunnel connection or consumes capacity reserved by already-admitted Visitor traffic.
- Authorization replacement, Tunnel-pool realignment, selective revocation, readiness, and orderly shutdown retain their existing behavior. Connections keep their active-admission accounting while moving between pools. Existing healthy connections are grandfathered if realignment combines pools above the per-Tunnel admission limit; new connections remain rejected until churn restores capacity.
- Transient public accept failures retry with exponential backoff from 10 ms to a 1-second cap. Other accept errors drop readiness and remain fatal.
- Saturation warnings include active work and the applicable limit and are rate-limited per scope to one every 10 seconds. Repetitive unauthorized-identity and QUIC handshake-failure warnings use the same rate bound; recovery is emitted once when capacity becomes available. Logs do not add remote Tunnel socket addresses or buffered ClientHello data.

## Tunnel authentication

The tunnel-connection trust model is:

1. the Server presents a certificate for `server.hostname`
2. the Client validates that certificate through system trust or through `client.server-trust = "ca-file"` with an exclusive CA bundle
3. the Client presents its own certificate
4. the Server verifies one of the Tunnel's pinned `client-identity` values from the Client public key

The pinned value is the client public key, not the certificate lifetime or serial number. Handshake admission and Public-hostname routing consult one shared **Authorization snapshot**, so identity additions and removals can replace admission without rebinding the tunnel listener. Live Tunnel connections retain their authenticated Client identity, and admitted Visitor streams retain their Public hostname and serving connection, so the runtime can dispatch targeted connection closes and stream resets without disturbing unrelated work.

Static fanout does not change these trust boundaries. When a Client dials multiple **Server addresses**, each **Tunnel connection** still uses the same shared Client identity, Server-certificate validation mode, and local Service-routing config.

## Control authentication (managed mode)

The Managed-session protocol, endpoints, and Control interoperability checklist are in [`managed.md`](managed.md). Managed mode introduces a separate trust boundary for the Control endpoint:

1. the Server authenticates to Control with **Server identity** material from `server.identity-dir`
2. the Client authenticates to Control with the same Client identity material used for Tunnel mTLS from `client.identity-dir`
3. the Client and Server validate the Control endpoint through `control.trust = "system"` or through `control.trust = "ca-file"` with an exclusive CA bundle
4. each **Managed session** requires mutually authenticated TLS with mandatory HTTP/2 ALPN; Core does not follow Control redirects and does not fall back to HTTP/1.1
5. each successfully handled snapshot is acknowledged once on that same authenticated connection with only the applied opaque revision; Core sends no periodic state heartbeat, and the acknowledgment does not represent **Server readiness** or **Assignment convergence**. State reporting stays off the downlink reconciliation critical path (at most one in-flight report and one coalesced latest revision) with 5-second request and response deadlines; success requires exact bodyless `204`
6. Managed-session SSE framing, snapshot bytes, decoded allocation, and role-input cardinalities are hard-bounded (documented in [`managed.md`](managed.md)); limit violations fail the session without partial apply and log only bounded metadata
7. Managed Server authorization and managed Client assignment apply through the role adapters documented in [`managed.md`](managed.md): atomic snapshot replacement, selective revocation or Retiring without local close, Control-loss retention of last-applied state, and nonzero exit only for unrecoverable post-commit or worker-task failures

**Server identity** is not the **Server certificate**. The Server certificate still identifies the tunnel endpoint to Clients. Server identity is a pinned public-key identity presented only to Control.

Identity and trust material are loaded when establishing each new Managed-session connection. Post-start reload failures remain recoverable in-process through the existing reconnect policy.

## Certificate and identity lifecycle

### Client identity

`runewarp client identity init` creates a Client keypair, an initial self-signed certificate, and `client-identity.txt`.

Self-hosted Client identity certificates are operationally non-expiring key carriers:

- newly initialized and rotated certificates use a **100-year** validity window
- the Server authorizes the pinned Client identity from the subject public key and does not validate certificate issuer, chain, SAN, validity window, or revocation state
- existing shorter-lived certificates remain accepted after their encoded expiry; Core does not rewrite them
- there is no automatic or manual self-signed Client identity certificate renewal

`runewarp client identity rotate` changes the key and therefore changes the identity.

### Server certificate

Runewarp supports two Server-certificate paths:

- ACME for the **Server hostname**
- a manual/private-CA path through `runewarp server cert init`, `renew`, and `rotate-ca`

In the manual/private-CA path:

- `runewarp server cert init` creates a private **Server CA** and an initial issued leaf
- `runewarp server cert renew` reissues the Server leaf from the same CA
- `runewarp server cert rotate-ca` changes the trust anchor itself, so Clients must trust a new CA

Existing QUIC connections continue with the certificate from their original handshake until they reconnect.

### Public hostname certificates (TLS termination)

When one or more Services use `tls-mode = "terminate"`, the Client needs public TLS certificates for those hostnames. Two mutually exclusive paths are supported:

**Manual path** (`client.public-cert-dir`) — operator creates and manages a private **Public hostname CA** and per-hostname leaf certificates:

- `runewarp client public-cert init` creates a private **Public hostname CA** and one or more initial **Public hostname certificates**, using `--hostname` or the config-derived terminating hostname set
- running it again with a different hostname reuses the existing CA and adds a new leaf without replacing the trust anchor
- the CA private key lives in `{public-cert-dir}/state/public-ca.key` and must be kept private

Visitors must trust `public-ca.crt`; it stays stable across additional `init` calls and leaf renewals, but `runewarp client public-cert rotate-ca` replaces it. Per-host certificate material lives at `{public-cert-dir}/{hostname}/public.crt` and `{public-cert-dir}/{hostname}/public.key`. **Public hostname certificates** are **90 days** by default; the **Public hostname CA** is **3650 days**.

**ACME path** (`[client.acme]`) — the Client automatically provisions and renews certificates from Let's Encrypt for the **Public hostnames** of all terminating Services. No pre-generated material is needed; configure `[client.acme]` in the Client config instead of `client.public-cert-dir`. The **Client instance** owns one live ACME manager per terminating **Public hostname** for the process lifetime (shared across Server-address workers and reconnects) without blocking on certificate readiness. Terminating hostnames without a ready certificate fail closed at the TLS handshake; there is no fallback to passthrough.

## ACME scope

Runewarp uses `rustls-acme` in **TLS-ALPN-01 only** mode. The current ACME config surface is fixed to Let's Encrypt.

### Server ACME

`[server.acme]` provisions the certificate for `server.hostname` only. When a Visitor connects to the Server hostname with ALPN `acme-tls/1`, the Server handles the challenge itself. All other application traffic addressed to the Server hostname is dropped.

- when omitted, `server.acme.state-dir` defaults to the XDG state path and is created at startup
- Runewarp warns when `server.public-bind-address` is not on TCP 443, but that warning stays advisory because the externally reachable public port may still be 443 through container or NAT mapping
- any explicit `server.acme.state-dir` should be protected like secret-bearing material

### Client ACME

`[client.acme]` provisions certificates for the **Public hostnames** of terminating Services. The managed hostname set is derived from every Service that has both `tls-mode = "terminate"` and explicit `public-hostnames`.

For Client ACME, `acme-tls/1` challenge connections for **Public hostnames** reach the Client through the Server's normal Visitor routing path — the Server does not inspect ALPN for Public hostname traffic and forwards the raw bytes to the Client through the Tunnel. The Client's ACME resolver handles both `acme-tls/1` challenge connections and regular TLS connections for those hostnames.

The **Client instance** owns one live ACME manager per terminating **Public hostname** for the process lifetime and does not block on certificate readiness. Independent Server-address workers and Tunnel-connection reconnects reuse that shared state; process shutdown stops and awaits the ACME tasks. Terminating hostnames without a ready ACME certificate fail closed at the TLS handshake; there is no fallback to passthrough.

- `client.acme.state-dir` defaults to the XDG client ACME state path and is created at startup when omitted
- Client ACME depends on the same public TCP 443 reachability at the Server edge because TLS-ALPN-01 challenge traffic still enters through the Server's public listener before it reaches the Client
- any explicit `client.acme.state-dir` should be protected like secret-bearing material

## Dependency advisory scanning

Core keeps a repository-owned RustSec gate at `./scripts/audit-dependencies`. That command requires the repository-pinned `cargo-audit` version, installs it through `cargo-binstall` when available, and falls back to a locked source install before scanning the resolved `Cargo.lock` graph. Vulnerabilities always fail. Informational findings (unmaintained, unsound, and yanked crates) also fail through `.cargo/audit.toml` (`output.deny = ["warnings"]`).

Checked-in exceptions belong only under `[advisories].ignore` in `.cargo/audit.toml`, each with the advisory id plus a comment that records why the finding is not exploitable or cannot yet be removed, an owner, and a removal condition. Do not blanket-ignore advisory classes.

CI bootstraps a pinned `cargo-binstall` release and runs the same command as a required Rust-contract step, avoiding a source build of the audit tool on fresh runners. Certificate and private-key PEM parsing uses maintained `rustls-pki-types` APIs rather than unmaintained `rustls-pemfile`.

## Operational limits and trade-offs

| Concern | Behavior |
| --- | --- |
| Cross-side hostname drift | The runtime does not validate cross-side hostname coverage under **Hostname mirroring** |
| Local backend health | There is no pre-flight Local backend health check |
| Manual/private-CA convenience | The simple manual path may keep private Server CA material on the public Server |
| Public hostname CA location | The manual path keeps the Public hostname CA private key on the Client machine alongside the running service |
| Same-Tunnel member policing | The runtime keeps a connected pool member in service even if that member rejects some placed streams; there is no automatic ejection or quarantine |

These are current limits, not hidden guarantees.
