# Runewarp

Runewarp is a private tunneling system for exposing operator-owned services without moving customer TLS termination onto the public edge. This glossary defines the canonical language for roles, routing, transport, trust, and lifecycle across Runewarp Core.

## Roles and components

**Core**:
The open-source Runewarp implementation, distinct from any compatible **Control**.
_Avoid_: control plane, managed service

**Server**:
The public Runewarp component that accepts **Visitor** traffic, selects a **Tunnel**, and forwards encrypted traffic to a **Client instance**.
_Avoid_: Edge proxy, gateway, node

**Server instance**:
One running process of the **Server** component. Multiple Server instances may temporarily overlap behind one **Server address** during replacement.
_Avoid_: Server, Server node, worker, replica

**Client**:
The Runewarp component that authenticates with a **Client identity** and forwards traffic between **Server instances** and **Local backends**.
_Avoid_: Visitor, browser, caller, agent

**Client instance**:
One running process of the **Client** component.
_Avoid_: Client, connection, replica

**Visitor**:
An unauthenticated outside party that connects to a routed **Public hostname** through Runewarp, whether directly or through a local client or wrapper.
_Avoid_: Client, user agent

**Local backend**:
The operator-run local endpoint that a **Client instance** connects to after selecting a **Service**. It terminates TLS under **TLS passthrough** and receives plaintext in **Terminate mode**.
_Avoid_: Service, tunnel

**Control**:
The external coordination endpoint that supplies **Managed mode** inputs and authenticates Server and Client roles over HTTPS.
_Avoid_: Control plane when referring to the runtime, tunnel endpoint, Server address

## Routing and hostnames

**Tunnel**:
A configured routing and trust unit that owns one slice of public traffic.
_Avoid_: Connection, session

**Tunnel ID**:
The **Control**-owned opaque identifier for one **Tunnel** in **Managed mode**, unique within an **Authorization snapshot** and used as the continuity key for that Tunnel's live **Tunnel pool**. **Static mode** has no Tunnel ID.
_Avoid_: tunnel UUID, ordinal, tunnel index

**Tunnel pool**:
The set of live **Tunnel connections** currently available for one **Tunnel** on one **Server instance**, regardless of which authorized **Client identity** each connection uses.
_Avoid_: Tunnel, cluster, active client pool

**Public listener**:
A **Server instance** TCP listener that accepts **Visitor** TLS traffic and **Server ACME** challenges.
_Avoid_: Tunnel listener, ingress proxy

**Tunnel listener**:
A **Server instance** UDP listener that accepts **Client instance** **Tunnel connections**.
_Avoid_: Public listener

**Public hostname**:
An operator-owned application hostname that a **Server** routes through a **Tunnel**.
_Avoid_: Server hostname, tunnel hostname

**Server hostname**:
The DNS hostname that identifies the public Runewarp Server endpoint itself, never an operator application.
_Avoid_: Public hostname, app hostname, server address

**Server address**:
The Client-configured network endpoint that a **Client instance** dials for its **Tunnel connection**, written as a DNS hostname with an optional port. Its host part is the **Server hostname**.
_Avoid_: Server hostname, bind address

**Control address**:
The DNS hostname with optional port that identifies the **Control** endpoint. HTTPS is mandatory and inferred.
_Avoid_: Server address, URL

**Public hostname authorization**:
The Server-owned rule that allows a **Tunnel** to admit traffic only for its explicit **Public hostnames**.
_Avoid_: Client registration, wildcard routing

**Authorization snapshot**:
The immutable Server-owned set of **Public hostname authorizations** and trusted **Client identities** used together for routing and handshake admission.
_Avoid_: Tunnel registry, handshake config, routing table

**Server-authoritative routing**:
The routing model where the **Server** chooses the **Tunnel** from **Public hostname authorization**, and the **Client** only performs **Service hostname matching** after that selection.
_Avoid_: Client registration, Client-authoritative routing

**Service**:
A Client-side routing unit that maps incoming admitted traffic to one **Local backend**.
_Avoid_: Backend, process, app

**Service hostname matching**:
The Client-side rule that selects a **Service** from explicit **Public hostnames** after traffic has already been admitted into a **Tunnel**.
_Avoid_: Public hostname authorization, Client registration

**Catch-all Service**:
The sole configured **Service** in a Client configuration when it omits explicit **Public hostnames**, receiving every hostname admitted into its **Tunnel**.
_Avoid_: Default service, wildcard service

**Hostname mirroring**:
The operator practice of repeating explicit **Public hostnames** in Server **Tunnels** and Client **Services** so both sides route the same traffic independently, even when their groupings differ.
_Avoid_: Duplicate hostname config, registration

## Tunnel transport and traffic

**Tunnel connection**:
A live authenticated session opened by one **Client instance** to one **Server instance** and accepted under one **Tunnel**.
_Avoid_: Tunnel, route

**Tunnel event stream**:
The Client-opened event subscription on one **Tunnel connection** through which a **Server instance** sends full state snapshots containing its **Server runtime generation** and any **Replacement hint**. It never carries configuration.
_Avoid_: control channel, association SSE, Managed session

**Server runtime generation**:
An opaque identifier minted at every start of one **Server instance** to distinguish one running incarnation from another behind the same **Server address**. It is not a credential, certificate, or enrollment identity.
_Avoid_: Server version, instance ID, Blue/Green

**Replacement hint**:
An optional **Server runtime generation** that a **Server instance** advertises on its **Tunnel event stream** to name another **Server instance** behind the same **Server address**. It carries no address, credential, or configuration.
_Avoid_: redirect, migration target, failover address

**Candidate Tunnel connection**:
A second **Tunnel connection** a **Client instance** opens to the same **Server address** while a **Replacement hint** stands, joining as a second active connection only after reaching the hinted **Server runtime generation**. Streams never move to it, and it never counts for **Client assignment convergence** or **Client readiness**.
_Avoid_: standby connection, failover connection, migration

**Visitor stream**:
The bidirectional stream carrying exactly one **Visitor** through one **Tunnel connection**. Its two directions can finish independently.
_Avoid_: Receive slot, application stream, reverse stream, proxy

**Visitor credit**:
A **Client**-offered opportunity for a **Server instance** to open a **Visitor stream**, backed by reserved Client-instance handler capacity. Idle credit is unassigned capacity; an active Visitor retains its capacity until its stream ends.
_Avoid_: Receive slot, backend capacity, request slot

**TLS passthrough**:
The Visitor-traffic behavior where Runewarp forwards customer TLS without decrypting it on the public **Server**. The Server always uses TLS passthrough for routed traffic, and a **Service** preserves it by default.
_Avoid_: Raw proxy mode

**Terminate mode**:
The per-**Service** behavior where the **Client instance** terminates **Visitor** TLS itself and forwards plaintext TCP to the **Local backend**.
_Avoid_: Edge termination, decrypted mode

**TLS mode**:
The per-**Service** setting that chooses between **TLS passthrough** and **Terminate mode** on the **Client**.
_Avoid_: Server mode, tunnel mode

**Canonical Visitor TCP tuple**:
The normalized **Visitor** source and original destination IP addresses and ports carried on every **Visitor stream**, derived either from the accepted socket or from **Visitor PROXY v2 ingress**.
_Avoid_: accepted peer, forwarded headers, raw PROXY header

**Visitor PROXY v2 ingress**:
The optional strict **Public listener** mode that requires trusted peers to supply a valid PROXY protocol v2 TCP tuple on every **Visitor** connection. It is independent from **Backend PROXY v2 emission**.
_Avoid_: Visitor proxy, automatic PROXY detection, mixed ingress

**Backend PROXY v2 emission**:
The per-**Service** option that writes a freshly encoded PROXY protocol v2 header containing the **Canonical Visitor TCP tuple** to that **Local backend**. It is independent from **Visitor PROXY v2 ingress**.
_Avoid_: forwarding the ingress header, global backend emission

## Identities, certificates, and trust

**Client identity**:
The durable pinned public-key identity used by one or more **Client instances** to authenticate to **Server instances** and **Control**. Certificate renewal with the same key preserves the identity; key rotation changes it.
_Avoid_: Certificate, serial number

**Client identity certificate**:
The certificate that carries and attests a **Client identity** without defining it.
_Avoid_: Client identity, Server certificate

**Server identity**:
The durable pinned public-key identity a **Server** presents to **Control**, distinct from the **Server certificate** used on the **Tunnel listener**. Certificate renewal and process restart preserve it; key rotation changes it.
_Avoid_: Server certificate, Server hostname, serial number

**Server identity certificate**:
The certificate a **Server instance** presents to authenticate its **Server identity** to **Control**. It attests the identity without defining it.
_Avoid_: Server certificate, Server identity

**Server certificate**:
The certificate a **Server instance** presents for the **Server hostname** on the **Tunnel listener**.
_Avoid_: Public hostname certificate, app certificate, Server identity

**Server CA**:
The operator-managed private certificate authority used to issue a **Server certificate** on the manual Server certificate path.
_Avoid_: public CA, app CA

**Exclusive CA trust**:
The trust model where a peer validates a remote certificate only against a configured CA bundle instead of the system trust store.
_Avoid_: System trust, mixed trust

**Control trust**:
The **Server** and **Client** trust policy for validating the **Control** endpoint certificate, using either system roots or **Exclusive CA trust**.
_Avoid_: Server trust

**Server ACME**:
The automatic certificate path where a **Server instance** provisions and renews the **Server certificate** for the **Server hostname**.
_Avoid_: Client ACME, Public hostname ACME

**Certificate owner**:
The one cooperating **Server instance** on a host allowed to drive **Server ACME** and publish durable Server certificate state. Ownership lasts until that process exits.
_Avoid_: Renewal lease, rollout leader, account owner

**Serving snapshot**:
An immutable, validated **Server certificate** and matching private key used for ordinary Tunnel TLS while certificate acquisition or renewal is unavailable. It contains no ACME account or **Authorization snapshot** material and never answers ACME challenges.
_Avoid_: ACME state transfer, authorization export, passive ACME manager

**Consumed challenge route**:
An observed **Server hostname** TLS-ALPN path reaching the intended **Certificate owner**, distinct from desired ingress configuration, Visitor placement, and Tunnel selection.
_Avoid_: Promotion, routing intent, challenge readiness flag

**Certificate maintenance**:
The terminal **Server instance** condition that stops new admission when certificate safety or finite certificate recovery is exhausted. It never resumes a drained Server instance.
_Avoid_: Paused rollout, certificate fallback, rollback

**Public hostname certificate**:
The certificate presented to a **Visitor** for a **Public hostname** when a **Service** uses **Terminate mode**.
_Avoid_: Server certificate, public certificate

**Public hostname CA**:
The operator-managed private certificate authority used to issue **Public hostname certificates** on the manual Client certificate path.
_Avoid_: Server CA, public CA

**Client ACME**:
The automatic certificate path where a **Client instance** provisions and renews **Public hostname certificates** for **Public hostnames** of **Services** in **Terminate mode**.
_Avoid_: Server ACME, tunnel ACME

## Managed mode

**Static mode**:
The startup shape in which local configuration supplies Server authorization and Client **Server addresses**.
_Avoid_: Managed mode

**Managed mode**:
The startup shape in which **Control** supplies Server authorization or Client **Server address** assignments.
_Avoid_: Static mode, self-hosted baseline

**Managed session**:
The authenticated live relationship between one **Server instance** or **Client instance** and **Control** for receiving versioned snapshots and sending **Managed state documents**. It is separate from **Server readiness**, Visitor traffic, and **Tunnel connections**.
_Avoid_: Tunnel connection, data path, control channel

**Managed session incarnation**:
The **Control**-issued identity of one admitted **Managed session**, distinct from a **Server runtime generation** and authentication credentials. Reconnecting creates a different incarnation even while the same process keeps serving.
_Avoid_: Process generation, authorization token, WebTransport session ID

**Revision**:
The **Control**-owned opaque identifier for one complete **Managed mode** input snapshot. **Core** compares revisions for equality only and reports the last applied Revision in every **Managed state document**.
_Avoid_: version number, sequence number, generation

**Managed state document**:
The complete current state a Managed **Server instance** or **Client instance** sends to **Control**, carrying its applied **Revision** and current role facts with no deltas.
_Avoid_: State document, acknowledgment, heartbeat, status report

**Client assignment convergence**:
The Managed **Client instance** aggregate of whether assigned **Server addresses** have live **Tunnel connections**: Unconverged when none are connected, Partially converged when some are connected, and Converged when all are connected or the assignment is empty. **Retiring** addresses are excluded.
_Avoid_: Assignment convergence, Client readiness, readiness, applied revision

**Retiring**:
The Managed **Client instance** lifecycle state for a connected **Server address** removed from its assignment. Its live **Tunnel connection** stays open until remote Server closure or process shutdown and can be re-adopted if the address returns.
_Avoid_: drain, local close, cancelled

**Client readiness**:
The one-shot **Static mode** signal emitted when a **Client instance** establishes its first authenticated **Tunnel connection** to a configured **Server address**.
_Avoid_: Client assignment convergence, Server readiness

## Readiness, drain, and shutdown

**Server readiness**:
The externally observable ingress-admission signal for one **Server instance**. When it succeeds, new load-balanced **Visitor** traffic may land there; when it fails, new load-balanced traffic should stop landing there.
_Avoid_: Graceful shutdown, tunnel coverage, health

**Placement withdrawal**:
The terminal, Client-initiated removal of one **Tunnel connection** from new **Visitor** placement during graceful Client shutdown. Already-committed **Visitor streams** may finish; it never withdraws the **Client identity** or other connections.
_Avoid_: drain, DRAIN_ACK, disconnect

**Withdrawal quiescence**:
The state of a withdrawn **Tunnel connection** with no committed **Visitor streams** remaining. Idle **Visitor credit** does not prevent it.
_Avoid_: idle, drained, Reported quiescence

**Managed drain**:
The one-way, bounded drain **Control** requests from a running Managed **Server instance**. The Server instance drops **Server readiness**, refuses new **Tunnel connections** and Visitor placement, drains in-flight Visitors within its shutdown budget, and keeps running and reporting until terminated.
_Avoid_: shutdown, withdrawal, Retiring

**Reported quiescence**:
A live Managed **Server instance**'s report in its **Managed state document** that it is in a **Managed drain** with zero in-flight **Visitors**. Open **Tunnel connections** do not prevent reported quiescence.
_Avoid_: Zero Tunnels, readiness, rollout completion, Withdrawal quiescence

**Infrastructure drain**:
Graceful process shutdown of a **Server instance** or **Client instance** initiated by its process supervisor. Distinct from a **Managed drain** and from Managed authorization or assignment removal.
_Avoid_: Retiring, authorization revocation, assignment removal

**Graceful shutdown**:
The bounded orderly-shutdown lifecycle where a **Server instance** or **Client instance** stops accepting new work and gives already-placed **Visitor streams** a bounded window to finish before exit.
_Avoid_: Crash, readiness, Fast shutdown

**Fast shutdown**:
The orderly-shutdown lifecycle that skips the graceful-drain window while still sending a normal connection close before exit.
_Avoid_: Crash, Graceful shutdown

## Relationships

- A **Server** can run as one or more **Server instances**
- Each **Server instance** mints exactly one **Server runtime generation** at start
- A **Server address** targets one **Server** endpoint, which may be backed by more than one overlapping **Server instance** during replacement
- The host part of a **Server address** is a **Server hostname**
- A **Server hostname** identifies the public Server endpoint, never an operator application
- A **Server certificate** belongs to exactly one **Server hostname**
- A **Server CA** can issue one or more **Server certificates**
- **Server ACME** manages certificates only for the **Server hostname**, driven by at most one **Certificate owner** per host
- A **Server instance** uses its **Public listeners** for **Visitor** TLS and **Server ACME** challenges, and its **Tunnel listeners** for **Tunnel connections**
- A **Server instance** selects exactly one **Tunnel** for each routed **Public hostname** using its current **Authorization snapshot**
- A **Public hostname** is routed through exactly one **Tunnel** at a time
- **Public hostname authorization** belongs to exactly one **Tunnel**, which owns one or more explicit **Public hostnames**
- In **Managed mode**, each **Tunnel** has exactly one **Tunnel ID** within an **Authorization snapshot**
- A **Tunnel** authorizes one or more **Client identities**
- A **Tunnel pool** belongs to exactly one **Tunnel** on one **Server instance** and contains zero or more live **Tunnel connections** across any of that Tunnel's authorized **Client identities**
- A **Client** can run as one or more **Client instances**
- A **Client instance** uses exactly one **Client identity** at a time, while one **Client identity** may be shared by multiple **Client instances** and is authorized by at most one **Tunnel**
- A **Client instance** dials one or more **Server addresses** with one primary **Tunnel connection** per address, plus at most one **Candidate Tunnel connection** per address while a **Replacement hint** stands
- Each **Tunnel connection** belongs to exactly one **Tunnel**, one **Client instance**, and one **Server instance**
- A **Visitor** reaches a **Local backend** only as a **Visitor stream** carried over a **Tunnel connection**
- **Server-authoritative routing** applies **Public hostname authorization** before **Service hostname matching**
- A **Service** maps traffic from one or more **Public hostnames** (or all admitted hostnames for a sole **Catch-all Service**) to one **Local backend**
- A **Service** has exactly one **TLS mode**: **TLS passthrough** leaves TLS termination to the **Local backend**, while **Terminate mode** terminates TLS at the **Client instance** using a **Public hostname certificate**
- **Public hostname CA** and **Client ACME** manage **Public hostname certificates** only for **Services** in **Terminate mode**
- **Hostname mirroring** repeats one explicit set of **Public hostnames** across **Tunnels** and **Services**, without requiring one-to-one grouping
- Every **Visitor stream** carries a **Canonical Visitor TCP tuple**, independent of **Visitor PROXY v2 ingress** and **Backend PROXY v2 emission**
- A **Managed session** belongs to exactly one **Server instance** or **Client instance**, has one **Managed session incarnation** per admitted downlink, receives snapshots keyed by **Revision**, and reports **Managed state documents**
- **Server readiness** belongs to exactly one **Server instance**
- **Withdrawal quiescence** applies to one withdrawn **Tunnel connection**; **Reported quiescence** applies to one **Server instance** in a **Managed drain**

## Example dialogue

> **Dev:** "Two Server processes are overlapping behind `tunnel.example.com` during a rollout. Are those two **Servers**?"
> **Domain expert:** "They are two **Server instances** with distinct **Server runtime generations** behind one **Server address**."
>
> **Dev:** "If a user runs a local TLS wrapper on their laptop to reach a non-TLS service without any Runewarp credentials, is that a **Client**?"
> **Domain expert:** "No. A **Client** authenticates with a **Client identity**. An unauthenticated caller reaching a **Public hostname** is a **Visitor**, even when it uses a local wrapper."
>
> **Dev:** "I started a second **Client instance**. Did that create a second **Tunnel connection**?"
> **Domain expert:** "Yes. Each **Client instance** opens one primary **Tunnel connection** per configured **Server address**."
>
> **Dev:** "Can `tunnel.example.com` also be a **Public hostname** for an app?"
> **Domain expert:** "No. That is the **Server hostname**. Application traffic uses separate **Public hostnames**."
>
> **Dev:** "Is `tunnel.example.com:443` the **Server hostname**?"
> **Domain expert:** "No. That is the **Server address**. `tunnel.example.com` is the **Server hostname** inside it."
>
> **Dev:** "Is `localhost:8443` the **Service**?"
> **Domain expert:** "No. The **Service** is the routing rule in Client config. `localhost:8443` is the **Local backend** it selects."
>
> **Dev:** "What changes when a **Service** switches its **TLS mode**?"
> **Domain expert:** "Under **TLS passthrough** the **Client instance** forwards the TLS bytes unchanged and the **Local backend** terminates TLS. In **Terminate mode** the **Client instance** terminates TLS and the **Local backend** receives plaintext."
>
> **Dev:** "If I enable **Visitor PROXY v2 ingress**, does the **Local backend** automatically get a PROXY header?"
> **Domain expert:** "No. **Visitor PROXY v2 ingress** only supplies the **Canonical Visitor TCP tuple** at the Server. **Backend PROXY v2 emission** is opted in per **Service**."
>
> **Dev:** "If two **Client instances** share a key, do they have the same **Client identity**?"
> **Domain expert:** "Yes. The **Client identity** is the pinned public key. Certificate renewal preserves it; only key rotation changes it."
>
> **Dev:** "What is the difference between **Withdrawal quiescence** and **Reported quiescence**?"
> **Domain expert:** "**Withdrawal quiescence** means one Client-withdrawn **Tunnel connection** has no committed **Visitor streams** left. **Reported quiescence** means a **Server instance** in a **Managed drain** reports zero in-flight Visitors in its **Managed state document**."
>
> **Dev:** "If **Server readiness** fails, did the **Server instance** crash?"
> **Domain expert:** "No. **Server readiness** only controls whether new load-balanced ingress should land there. It drops during **Graceful shutdown**, **Managed drain**, and **Certificate maintenance**."
>
> **Dev:** "Why do both sides list `app.example.com`?"
> **Domain expert:** "That is **Hostname mirroring**. Under **Server-authoritative routing**, the **Server** checks **Public hostname authorization** to choose the **Tunnel**, and the **Client** uses **Service hostname matching** to choose the **Service**, unless the Client uses a sole **Catch-all Service**."

## Flagged ambiguities

- "Server" blurred the component with one running process, and "worker" or "Server node" drifted in for hosts and processes. Resolved: **Server** is the component, **Server instance** is one running process, and **Server runtime generation** distinguishes overlapping incarnations behind one **Server address**; use "host" for the machine running cooperating Server instances.
- "Client" blurred the operator component, one running process, and outside callers. Resolved: **Client** is the authenticated Runewarp component carrying a **Client identity**, **Client instance** is one running process, and **Visitor** is an unauthenticated outside caller (including any unauthenticated local wrapper).
- "Proxy" was overloaded across PROXY protocol v2 headers, live forwarded streams, and external load balancers. Resolved: use **Visitor PROXY v2 ingress** and **Backend PROXY v2 emission** for PROXY protocol v2, and **Visitor stream** instead of "proxy" for a live forwarded connection.
- "Quiescent" stretched across Client placement withdrawal and Server Managed drain. Resolved: **Withdrawal quiescence** is per withdrawn **Tunnel connection**; **Reported quiescence** is a Managed **Server instance** reporting draining with zero in-flight Visitors (matching Runewarp Cloud).
- Core and Cloud used slightly different names for shared Managed concepts. Resolved: aligned Core on **Managed state document**, **Client assignment convergence**, and **Reported quiescence**.
- "Tunnel" blurred the configured routing unit with a live session. Resolved: **Tunnel** is the configured unit, **Tunnel connection** is the live session, **Tunnel pool** is the set of live connections for one Tunnel on one Server instance, and **Tunnel ID** is the Managed-mode continuity key.
- "Server hostname", "Server address", and "Public hostname" were easy to blur. Resolved: **Server hostname** names the public Server endpoint, **Server address** is the Client-dialed DNS-hostname-and-port endpoint (never an IP literal), and **Public hostname** names operator application traffic.
- "Service" and "Local backend" were used interchangeably. Resolved: **Service** is the Client routing rule; **Local backend** is the dialed target endpoint.
- "Client certificate" and "Server certificate" blurred identities with presented leaves and issuers. Resolved: **Client identity** and **Server identity** are durable pinned public keys attested by identity certificates; **Server certificate** is the Tunnel endpoint leaf issued by **Server ACME** or a **Server CA**; **Public hostname certificate** is the Terminate-mode leaf issued by **Client ACME** or a **Public hostname CA**.
- "Readiness", "convergence", and shutdown modes were easy to blur. Resolved: **Server readiness** is the Server ingress-admission signal, **Client readiness** is the Static-mode one-shot connect signal, **Client assignment convergence** is Managed connection coverage, and **Graceful shutdown**, **Fast shutdown**, **Managed drain**, and **Infrastructure drain** each name a distinct lifecycle.
- "Control channel" and "managed service" blurred roles and transports. Resolved: **Control** is the external coordination endpoint, **Managed session** is the live relationship, and **Core** avoids calling itself or Control a "managed service".
- "Hostname mirroring" and "Catch-all Service" were easy to treat as one cross-side mode. Resolved: Server **Tunnels** always require explicit **Public hostnames**; Clients independently choose **Hostname mirroring** or a sole **Catch-all Service**.
