# Runewarp

Runewarp is a private tunneling system for exposing operator-owned TLS services without moving customer TLS termination onto the public edge. This context exists to keep the product language around routing, trust, and operator roles precise.

## Language

**Server**:
The public Runewarp component that accepts **Visitor** traffic, selects a **Tunnel**, and forwards encrypted traffic to a **Client**.
_Avoid_: Edge proxy, gateway

**Tunnel**:
A configured routing and trust unit that owns one slice of public traffic.
_Avoid_: Connection, session

**Tunnel connection**:
A live session opened by one **Client instance** and accepted under one **Tunnel**.
_Avoid_: Tunnel, route

**Client**:
The operator-run Runewarp component responsible for forwarding traffic between the **Server** and local backends.
_Avoid_: Visitor, browser, caller

**Client instance**:
One running copy of the **Client** component.
_Avoid_: Client, connection, replica

**Visitor**:
The outside party that connects to a routed **Public hostname** through Runewarp.
_Avoid_: Client, user agent

**Server hostname**:
The hostname that identifies the Runewarp public edge itself.
_Avoid_: Public hostname, app hostname, server address

**Server address**:
The client-configured network endpoint that a **Client instance** dials for its **Tunnel connection**, written as a hostname with an optional port. Its host part is also the TLS identity for the tunnel connection.
_Avoid_: Server hostname, bind address

**Server certificate**:
The certificate the **Server** presents for the **Server hostname** on the tunnel endpoint.
_Avoid_: Public hostname certificate, app certificate

**Exclusive CA trust**:
The Client trust model where the **Client** validates the **Server certificate** only against a configured CA bundle instead of the system trust store.
_Avoid_: System trust, mixed trust

**Server CA**:
The operator-managed private certificate authority used to issue a **Server certificate** in the manual Server-certificate path.
_Avoid_: public CA, app CA

**Server ACME**:
The automatic certificate path where the **Server** provisions and renews a certificate for the **Server hostname**.
_Avoid_: Client ACME, Public hostname ACME

**Public hostname CA**:
The operator-managed private certificate authority used to issue **Public hostname certificates** for Services in **Terminate mode** on the manual Client certificate path.
_Avoid_: Server CA, public CA

**Client ACME**:
The automatic certificate path where the **Client** provisions and renews **Public hostname certificates** for **Public hostnames** of Services in **Terminate mode**.
_Avoid_: Server ACME, tunnel ACME

**Public hostname**:
An operator-owned application hostname that the **Server** routes through a **Tunnel**.
_Avoid_: Server hostname, tunnel hostname

**Public hostname authorization**:
The Server-owned rule that allows a **Tunnel** to admit traffic only for its explicit **Public hostnames**.
_Avoid_: Client registration, wildcard routing

**Authorization snapshot**:
The immutable Server-owned Public-hostname routing and trusted Client-identity set that Public-hostname routing and QUIC Client-identity handshake admission consult together. Static configuration loads one snapshot at startup; a prepared replacement can be validated independently and committed atomically.
_Avoid_: Tunnel registry, handshake config, routing table

**Address controller**:
The Client-owned runtime that maintains at most one address worker per normalized **Server address**, and that can replace maintenance intent through add, remove, and re-adopt operations without process restart. Static Client startup seeds it from the configured address set; Managed-session reconciliation builds on the same seam later.
_Avoid_: fanout loop, connection pool, dial manager

**Control**:
The managed-service endpoint that assigns configuration and authenticates Server and Client roles over HTTPS.
_Avoid_: tunnel endpoint, Server address

**Control address**:
The DNS hostname with optional port that identifies the Control endpoint. Written without a scheme; HTTPS is mandatory and inferred.
_Avoid_: Server address, URL

**Managed mode**:
Configuration and runtime shape where an effective Control address is present. Managed Servers omit static `[[server.tunnels]]` authorization and use `server.identity-dir`. Managed Clients omit static Server addresses.
_Avoid_: static mode, self-hosted baseline

**Server identity**:
The pinned public-key identity the Server presents to Control, distinct from the **Server certificate** used on the tunnel endpoint.
_Avoid_: Server certificate, Client identity

**Public hostname certificate**:
The certificate presented to a **Visitor** for a **Public hostname** when a **Service** is in **Terminate mode**.
_Avoid_: Server certificate, public certificate

**Service**:
A client-side routing unit that maps incoming traffic to one **Local backend**.
_Avoid_: Backend, process, app

**Service hostname matching**:
The Client-side rule that selects a **Service** from explicit **Public hostnames** after traffic has already been admitted into a **Tunnel**.
_Avoid_: Public hostname authorization, Client registration

**TLS passthrough**:
The Visitor-traffic behavior where Runewarp forwards customer TLS without decrypting it on the public edge. The **Server** always uses **TLS passthrough** for routed application traffic, and a **Service** preserves that behavior when its `tls-mode` is `passthrough`.
_Avoid_: Raw proxy mode

**Terminate mode**:
The **Service** behavior selected by `tls-mode = "terminate"`, where the **Client** terminates TLS itself and forwards plaintext TCP to the **Local backend**.
_Avoid_: Edge termination, decrypted mode

**TLS mode**:
The **Service** setting that chooses whether traffic stays in **TLS passthrough** or switches to **Terminate mode** at the **Client**.
_Avoid_: Server mode, tunnel mode

**Local backend**:
The operator-run local endpoint that a **Client** connects to after it selects a **Service**. It terminates TLS under **TLS passthrough** and receives plaintext in **Terminate mode**.
_Avoid_: Service, tunnel

**Client identity**:
The stable trust identity used by one or more **Client instances**, defined by its pinned public key rather than a certificate lifetime or issuer; self-signed Client identity certificates are operationally non-expiring key carriers, and Cloud-issued attestation preserves it, while explicit key rotation changes the identity. One **Tunnel** may authorize one or more **Client identities**.
_Avoid_: Certificate, serial number

**Server identity**:
The stable trust identity used by one or more **Servers**, defined by its pinned public key rather than a certificate lifetime or issuer. Certificate renewal and process restarts preserve it; key rotation changes it.
_Avoid_: Server certificate, Server hostname, serial number

**Server identity certificate**:
The certificate a **Server** presents to authenticate its **Server identity** to a managed control plane. It attests the identity without defining it, so renewal with the same key preserves the **Server identity**.
_Avoid_: Server certificate, Server identity

**Managed session**:
The authenticated live relationship between one **Server** or **Client instance** and a managed control plane for receiving versioned full-input snapshots and reporting the last successfully applied opaque revision. Core establishes it as one mutually authenticated HTTP/2 connection with a single role-specific SSE downlink plus concurrent state-report streams; it is separate from Visitor traffic and **Tunnel connections**.
_Avoid_: Tunnel connection, data path, control channel

**Tunnel pool**:
The set of live **Tunnel connections** and their serving **Client instances** currently available for one **Tunnel**, regardless of which authorized **Client identity** each member uses.
_Avoid_: Tunnel, cluster

**Server readiness**:
The externally observable ingress-admission signal for a **Server**. When **Server readiness** succeeds, new load-balanced visitor traffic may be admitted. When it fails, no new load-balanced visitor traffic should land there. In **Managed mode**, readiness stays unavailable until the first successful Server input apply, then remains available through later Control loss while the last applied authorization is retained.
_Avoid_: Graceful shutdown, tunnel coverage, health

**Graceful shutdown**:
The bounded orderly-shutdown lifecycle for a Runewarp component where shutdown behavior is deliberate rather than abrupt. For a **Server**, this includes leaving readiness immediately and allowing already-landed visitor work a bounded wind-down before exit; in **Managed mode**, the **Managed session** stays active through that drain so Authorization changes still apply, and the session ends only when the HTTP/2 connection closes at final process exit. For a **Client**, this includes orderly tunnel-connection shutdown behavior before exit.
_Avoid_: Crash, readiness, Fast shutdown

**Fast shutdown**:
The orderly-shutdown lifecycle for a Runewarp component that skips the longer graceful-drain window but still sends the normal QUIC close and keeps the short **QUIC close flush duration** before exit.
_Avoid_: Crash, Graceful shutdown

**QUIC close flush duration**:
The short fixed time after Runewarp sends a normal QUIC connection close during orderly shutdown, giving that close a chance to flush before process exit. It is separate from any longer graceful-drain duration.
_Avoid_: Graceful shutdown duration, stream drain timeout

**Server-authoritative routing**:
The routing rule where the **Server** chooses the **Tunnel** from **Public hostname authorization**, and the **Client** only performs **Service hostname matching** after that selection.
_Avoid_: Client registration, Client-authoritative routing

**Catch-all Service**:
The only configured **Service** in a Client config, which receives every proxied **Public hostname**; this is determined by the Client side alone.
_Avoid_: Default service, wildcard service

**Hostname mirroring**:
The operator practice of repeating **Public hostnames** in Server **Tunnels** and Client **Services** when both sides use explicit hostname matching, so both sides can route the same traffic without extra protocol metadata even when their grouping differs.
_Avoid_: Duplicate hostname config, registration

**Config preparation**:
The internal module that selects the active config input, applies CLI/XDG/hardcoded defaults, resolves config-relative paths, and emits prepared **Server** or **Client** config before validation and startup side effects.
_Avoid_: Settings loader, validation pass, startup defaults

**Release-prep PR**:
The maintainer change that prepares one stable release by updating versioned release metadata on `main` before the real release tag is cut.
_Avoid_: Release branch, release commit

**Release rehearsal**:
The non-publishing release validation run that exercises the release gates for one candidate stable version already reachable from `main`.
_Avoid_: Real release, preview publish

**Release tag**:
The SSH-signed stable `vX.Y.Z` tag that triggers real public publication for one release.
_Avoid_: Commit, branch tag

**Release environment**:
The GitHub environment that scopes release-only secrets to the privileged publication jobs.
_Avoid_: CI environment, deploy target

## Relationships

- A **Server** selects exactly one **Tunnel** for each routed **Public hostname**
- A **Client** can run as one or more **Client instances**
- A **Tunnel** can have zero or more live **Tunnel connections**
- A **Tunnel** authorizes one or more **Client identities**
- Each **Tunnel connection** belongs to exactly one **Tunnel**
- Each **Tunnel connection** belongs to exactly one **Client instance**
- A **Client instance** establishes one or more **Tunnel connections**
- A **Client instance** dials one or more **Server addresses**, with one **Tunnel connection** per **Server address**
- A **Visitor** reaches a **Local backend** only through a **Tunnel**
- A **Server address** points at exactly one **Server**
- A **Server hostname** identifies the public edge, not an operator application
- The host part of a **Server address** is the **Server hostname**
- A **Server certificate** belongs to exactly one **Server hostname**
- **Exclusive CA trust** validates the **Server certificate** against exactly one configured CA bundle
- A **Server CA** can issue one or more **Server certificates**
- **Server ACME** manages certificates only for the **Server hostname**
- A **Public hostname CA** can issue one or more **Public hostname certificates** for Services in **Terminate mode**
- **Client ACME** manages certificates only for **Public hostnames** of Services in **Terminate mode**
- A **Public hostname** is routed through exactly one **Tunnel** at a time
- **Public hostname authorization** belongs to exactly one **Tunnel**
- A **Public hostname certificate** belongs to exactly one **Public hostname**
- A **Service** maps traffic from one or more **Public hostnames** to one **Local backend**
- **Service hostname matching** belongs to exactly one **Service**
- The **Server** preserves **TLS passthrough** for routed application traffic
- A **Service** has exactly one **TLS mode**
- Under **TLS passthrough**, a **Local backend** terminates TLS for the selected **Service**
- In **Terminate mode**, the **Client** terminates TLS before forwarding traffic to the **Local backend**
- A **Client instance** forwards proxied traffic from its **Tunnel connection** to a **Local backend** through a selected **Service**
- A **Client instance** uses exactly one **Client identity** at a time
- A **Client identity** can be used by one or more **Client instances**
- A **Client identity** is authorized by exactly one **Tunnel**
- A **Managed session** belongs to exactly one **Server** or **Client instance**
- A **Tunnel pool** belongs to exactly one **Tunnel**
- A **Tunnel pool** may contain members using different authorized **Client identities** of that **Tunnel**
- A **Server readiness** signal belongs to exactly one **Server**
- A **Graceful shutdown** applies to exactly one running Runewarp component at a time
- A **Fast shutdown** applies to exactly one running Runewarp component at a time
- **Server-authoritative routing** uses **Public hostname authorization** before **Service hostname matching**
- A **Tunnel** owns one or more explicit **Public hostnames**
- A **Catch-all Service** is valid only when there is exactly one configured **Service**
- **Hostname mirroring** repeats one set of **Public hostnames** across **Tunnels** and **Services**, but the grouping does not have to line up one-to-one
- A **Release-prep PR** prepares exactly one candidate stable release
- A **Release rehearsal** validates exactly one candidate **Release tag** without publishing public artifacts
- A **Release tag** publishes exactly one stable release from a green commit already on `main`
- A **Release environment** scopes secrets for real publication jobs only

## Example dialogue

> **Dev:** "I started a second **Client instance** — did that create a second **Tunnel connection**?"
> **Domain expert:** "Yes. Each **Client instance** owns one **Tunnel connection** per configured **Server address**."
>
> **Dev:** "The **Visitor** hit the public hostname, but which **Client** served it?"
> **Domain expert:** "Whichever **Client instance** owned the selected **Tunnel connection** for that **Tunnel**."
>
> **Dev:** "Can `tunnel.example.com` also be a **Public hostname** for an app?"
> **Domain expert:** "No. That is the **Server hostname**. Application traffic uses separate **Public hostnames**."
>
> **Dev:** "Is `tunnel.example.com:443` the **Server hostname**?"
> **Domain expert:** "No. That is the **Server address**. `tunnel.example.com` is the **Server hostname** inside it."
>
> **Dev:** "Is the `localhost:8443` target the **Service**?"
> **Domain expert:** "No. The **Service** is the routing rule in client config. `localhost:8443` is the **Local backend** it selects."
>
> **Dev:** "What changes when a **Service** switches its **TLS mode**?"
> **Domain expert:** "Under **TLS passthrough** the **Client** forwards the TLS bytes unchanged and the **Local backend** terminates TLS. In **Terminate mode** the **Client** terminates TLS and the **Local backend** receives plaintext."
>
> **Dev:** "If I start two **Client instances**, do they need different **Client identities**?"
> **Domain expert:** "No. They may share one **Client identity** or use separate ones."
>
> **Dev:** "If the self-signed Client identity certificate expires, did the **Client identity** change?"
> **Domain expert:** "No. The **Client identity** is the pinned public key. Encoded certificate expiry has no operational effect in pinned-key mode; only explicit key rotation changes the identity."
>
> **Dev:** "If Cloud signs a certificate for the Client's existing public key, does Cloud now own the **Client identity**?"
> **Domain expert:** "No. The public key remains the **Client identity**, and the customer retains its private key. Cloud's certificate only attests that identity."
>
> **Dev:** "Why does the manual Server path trust a **Server CA** instead of the leaf cert directly?"
> **Domain expert:** "Because the **Server CA** signs the **Server certificate**, so the Server leaf can renew without changing the Client's trust anchor."
>
> **Dev:** "What changes when the Client uses **Exclusive CA trust**?"
> **Domain expert:** "The **Client** trusts only the configured CA bundle for the **Server certificate** instead of also trusting the system roots."
>
> **Dev:** "What is the difference between **Server ACME** and **Client ACME**?"
> **Domain expert:** "**Server ACME** manages the certificate for the **Server hostname**. **Client ACME** manages **Public hostname certificates** for terminating **Public hostnames** on the **Client** side."
>
> **Dev:** "Why do both sides list `app.example.com`?"
> **Domain expert:** "That's **Hostname mirroring**. The **Server** uses it to choose the **Tunnel** and the **Client** uses it to choose the **Service**."
>
> **Dev:** "If readiness fails, does that mean the Server crashed?"
> **Domain expert:** "No. **Server readiness** is only the ingress-admission signal. It can fail during **Graceful shutdown** without implying an abrupt crash."
>
> **Dev:** "Is fast shutdown just a crash with a nicer name?"
> **Domain expert:** "No. **Fast shutdown** is still orderly. It sends the normal QUIC close and keeps the short **QUIC close flush duration**, but it skips the longer graceful-drain window."
>
> **Dev:** "Is a graceful Ctrl-C window the same thing as ingress readiness?"
> **Domain expert:** "No. Core calls that **Graceful shutdown**. **Server readiness** is the separate ingress-admission signal."
>
> **Dev:** "So who actually owns ingress routing?"
> **Domain expert:** "**Server-authoritative routing** means the **Server** chooses the **Tunnel** first. The **Client** only matches the traffic to a **Service** after that."
>
> **Dev:** "What prevents a connected Client from receiving some random hostname?"
> **Domain expert:** "**Public hostname authorization**. The **Server** only admits traffic for the explicit **Public hostnames** owned by that **Tunnel**."
>
> **Dev:** "Then what do the Client-side hostnames do?"
> **Domain expert:** "**Service hostname matching**. They choose the **Service** after the **Server** has already admitted the traffic into the **Tunnel**."
>
> **Dev:** "Why did omitting the **Public hostnames** suddenly change routing behavior?"
> **Domain expert:** "Because this config uses a **Catch-all Service**. The Server still has to list explicit **Public hostnames** on its **Tunnels**."
>
> **Dev:** "If the **Server** uses exact-match **Tunnels**, does the **Client** also have to use exact-match **Services**?"
> **Domain expert:** "No. A **Catch-all Service** is still valid when the Client has exactly one **Service**. Catch-all vs exact-match is decided independently on each side."
>
> **Dev:** "Is that still **Hostname mirroring** if the **Client** uses a **Catch-all Service**?"
> **Domain expert:** "No. **Hostname mirroring** is only when both sides repeat explicit **Public hostnames**. Here the **Client** is using a **Catch-all Service** instead."
>
> **Dev:** "If the **Server** puts `app.example.com` and `api.example.com` in one **Tunnel**, but the **Client** splits them across two **Services**, is that still **Hostname mirroring**?"
> **Domain expert:** "Yes. **Hostname mirroring** repeats the hostname set across both sides; the grouping into **Tunnels** and **Services** can differ."
>
> **Dev:** "What actually starts a public release?"
> **Domain expert:** "A signed **Release tag** on a green `main` commit. A **Release rehearsal** checks the same gates without publishing."
>
> **Dev:** "Where do I make the version and changelog changes first?"
> **Domain expert:** "In the **Release-prep PR**. The tag comes later, after that candidate commit is on `main` and green."

## Flagged ambiguities

- "tunnel" was used to mean both a configured routing entry and a live QUIC session — resolved: **Tunnel** is the configured unit; **Tunnel connection** is the live session.
- "client" was used to mean both the operator-run component and the outside network peer — resolved: **Client** is the operator-run component; **Visitor** is the outside public caller.
- "client" was also used to blur the component and one running process — resolved: **Client** is the component; **Client instance** is one running copy.
- "server hostname" and routed application hostnames were easy to blur — resolved: **Server hostname** names the Runewarp edge; **Public hostname** names operator application traffic.
- "server address" and "server hostname" were easy to blur — resolved: **Server address** is the client-configured endpoint; **Server hostname** is the hostname form of that endpoint when a hostname is used.
- "service" and "backend" were used interchangeably — resolved: **Service** is the client-side config unit; **Local backend** is the actual local endpoint the **Client** dials, whether it terminates TLS or receives plaintext.
- "passthrough" could blur Server behavior with Service behavior — resolved: **TLS passthrough** is the broad traffic behavior, while **TLS mode** is the **Service** setting that can keep passthrough or switch to **Terminate mode**.
- "client certificate" and the durable trust anchor were easy to conflate — resolved: **Client identity** is the pinned public key; the self-signed certificate is only a key carrier, and only explicit key rotation changes that identity.
- "Cloud-signed Client" could imply Cloud-owned key material — resolved: Cloud may attest an existing **Client identity**, but the customer retains the private key and identity ownership.
- "control channel" could blur a live relationship with its eventual transport — resolved: **Managed session** names the relationship; Core implements it as mutually authenticated HTTP/2 with one role-specific SSE downlink.
- "server certificate" and the trust anchor behind it were easy to conflate — resolved: **Server certificate** is the presented leaf; **Server CA** is the private issuer in the manual Server path.
- "ca-file trust" sounded like a file-path detail instead of a trust model — resolved: **Exclusive CA trust** means the **Client** trusts only the configured CA bundle for the **Server certificate**.
- "public CA" was too vague once Client-side TLS termination existed — resolved: **Public hostname CA** is the issuer for manual **Public hostname certificates**, distinct from the **Server CA**.
- "readiness" and orderly exit were easy to blur — resolved: **Server readiness** is the ingress-admission signal, while **Graceful shutdown** is the bounded orderly-exit lifecycle.
- "graceful" and "fast" shutdown were easy to blur — resolved: both are orderly shutdown modes, but **Fast shutdown** skips the longer graceful-drain window while keeping the short **QUIC close flush duration**.
- "ACME" was too broad once both sides could obtain certificates automatically — resolved: **Server ACME** covers the **Server hostname** only, while **Client ACME** covers terminating **Public hostnames** only.
- "authorized hostname" was being described ad hoc — resolved: **Public hostname authorization** is the Server-owned rule that binds explicit **Public hostnames** to a **Tunnel**.
- "hostnames on Services" looked like the same mechanism as the Server side — resolved: **Service hostname matching** is a Client-side routing decision after Server admission, not a second authorization layer.
- "who routes traffic?" was easy to answer loosely — resolved: **Server-authoritative routing** means the **Server** chooses the **Tunnel**, while the **Client** only chooses the **Service** within that admitted traffic.
- "catch-all" looked like casual prose, but it changes config semantics — resolved: only **Catch-all Service** remains a valid product term; Server **Tunnels** always require explicit **Public hostnames**.
- "catch-all mode" could sound like one cross-side mode — resolved: we describe the Client behavior directly as a **Catch-all Service** instead of inventing a separate topology name.
- "Hostname mirroring" could sound like it covered every valid routing topology — resolved: **Hostname mirroring** means both-sides explicit hostname matching; a **Catch-all Service** on the Client is described directly rather than named as a separate topology.
- "Hostname mirroring" could sound like Tunnel and Service groups had to line up exactly — resolved: the mirrored unit is the explicit hostname set, not a one-to-one grouping.
- "duplicate hostname config" sounded accidental — resolved: **Hostname mirroring** is the deliberate routing pattern.
- "release" could blur rehearsal with real publication — resolved: **Release rehearsal** is the non-publishing gate run, while a **Release tag** starts the real published release.
