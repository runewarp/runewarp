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
A live session accepted under a **Tunnel** and used to carry proxied public streams.
_Avoid_: Tunnel, route

**Client**:
The operator-run Runewarp component that stays connected to the **Server** and forwards traffic to local backends.
_Avoid_: Visitor, browser, caller

**Visitor**:
The outside party that connects to a routed **Public hostname** through Runewarp.
_Avoid_: Client, user agent

**Server hostname**:
The hostname that identifies the Runewarp public edge itself.
_Avoid_: Public hostname, app hostname

**Public hostname**:
An operator-owned application hostname that the **Server** routes through a **Tunnel**.
_Avoid_: Server hostname, tunnel hostname

**Service**:
A client-side routing unit that maps incoming traffic to one **Local backend**.
_Avoid_: Backend, process, app

**Local backend**:
The operator-run TLS-terminating process or endpoint that a **Client** connects to after it selects a **Service**.
_Avoid_: Service, tunnel

**Client identity**:
The stable trust identity of a **Client**, defined by its pinned public key rather than a certificate lifetime.
_Avoid_: Certificate, serial number

**Tunnel pool**:
The set of live **Tunnel connections** currently serving one **Tunnel** under one **Client identity**.
_Avoid_: Tunnel, cluster

**Catch-all Tunnel**:
The only configured **Tunnel** in a Server config, which matches every routed **Public hostname** except the **Server hostname**.
_Avoid_: Default tunnel, wildcard tunnel

**Catch-all Service**:
The only configured **Service** in a Client config, which receives every proxied **Public hostname**.
_Avoid_: Default service, wildcard service

**Hostname mirroring**:
The operator practice of repeating **Public hostnames** in Server **Tunnels** and Client **Services** so both sides can route the same traffic without extra protocol metadata.
_Avoid_: Duplicate hostname config, registration

## Relationships

- A **Server** selects exactly one **Tunnel** for each routed **Public hostname**
- A **Tunnel** can have zero or more live **Tunnel connections**
- Each **Tunnel connection** belongs to exactly one **Tunnel**
- A **Client** can establish zero or more **Tunnel connections**
- A **Visitor** reaches a **Local backend** only through a **Tunnel**
- A **Server hostname** identifies the public edge, not an operator application
- A **Public hostname** is routed through exactly one **Tunnel** at a time
- A **Service** maps traffic from one or more **Public hostnames** to one **Local backend**
- A **Client** forwards proxied traffic from a **Tunnel connection** to a **Local backend** through a selected **Service**
- A **Tunnel** trusts exactly one **Client identity** in the base model
- A **Tunnel pool** contains only **Tunnel connections** accepted under that **Client identity**
- A **Catch-all Tunnel** is valid only when there is exactly one configured **Tunnel**
- A **Catch-all Service** is valid only when there is exactly one configured **Service**
- **Hostname mirroring** repeats one set of **Public hostnames** across **Tunnels** and **Services**

## Example dialogue

> **Dev:** "The client reconnected — did we create a new **Tunnel**?"
> **Domain expert:** "No. We created a new **Tunnel connection** for the same **Tunnel**."
>
> **Dev:** "The **Visitor** hit the public hostname, but which **Client** served it?"
> **Domain expert:** "Whichever **Client** currently had the selected **Tunnel connection** for that **Tunnel**."
>
> **Dev:** "Can `tunnel.example.com` also be a **Public hostname** for an app?"
> **Domain expert:** "No. That is the **Server hostname**. Application traffic uses separate **Public hostnames**."
>
> **Dev:** "Is the `caddy.local:443` target the **Service**?"
> **Domain expert:** "No. The **Service** is the routing rule in client config. `caddy.local:443` is the **Local backend** it selects."
>
> **Dev:** "The certificate renewed — did the **Client identity** change?"
> **Domain expert:** "No. The **Client identity** is the pinned public key. Renewal keeps the same identity unless the key changes."
>
> **Dev:** "Why do both sides list `app.example.com`?"
> **Domain expert:** "That's **Hostname mirroring**. The **Server** uses it to choose the **Tunnel** and the **Client** uses it to choose the **Service**."
>
> **Dev:** "Why did omitting `hostnames` suddenly change routing behavior?"
> **Domain expert:** "Because this config uses a **Catch-all Tunnel** and a **Catch-all Service**, which are only valid when each side has exactly one entry."

## Flagged ambiguities

- "tunnel" was used to mean both a configured routing entry and a live QUIC session — resolved: **Tunnel** is the configured unit; **Tunnel connection** is the live session.
- "client" was used to mean both the operator-run component and the outside network peer — resolved: **Client** is the operator-run component; **Visitor** is the outside public caller.
- "server hostname" and routed application hostnames were easy to blur — resolved: **Server hostname** names the Runewarp edge; **Public hostname** names operator application traffic.
- "service" and "backend" were used interchangeably — resolved: **Service** is the client-side config unit; **Local backend** is the actual TLS endpoint the **Client** dials.
- "client certificate" and the durable trust anchor were easy to conflate — resolved: **Client identity** is the pinned public key, while certificates can rotate without changing that identity.
- "catch-all" looked like casual prose, but it changes config semantics — resolved: **Catch-all Tunnel** and **Catch-all Service** are explicit single-entry modes.
- "duplicate hostname config" sounded accidental — resolved: **Hostname mirroring** is the deliberate routing pattern.
