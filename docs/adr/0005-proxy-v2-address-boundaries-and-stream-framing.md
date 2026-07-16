# PROXY v2 address boundaries and stream framing

## Status

Accepted

## Context

Runewarp can accept Visitors directly or behind a TCP load balancer, while Local backends independently decide whether they can consume PROXY protocol. Passing an upstream header through unchanged would couple those trust boundaries and retain unneeded metadata. Carrying the canonical address tuple on Tunnel streams changes the existing `runewarp/1` application-stream framing.

## Decision

The Server normalizes direct socket addresses or a trusted strict-PROXY-v2 header into one **Canonical Visitor TCP tuple**. Every Server-opened `runewarp/1` application stream starts with a newly encoded PROXY v2 TCP header containing that tuple. The Client always validates and consumes this internal header, then independently regenerates a PROXY v2 header only for Services that opt into **Backend PROXY emission**.

The `runewarp/1` ALPN remains unchanged. Mixed binaries using old and new application-stream framing are unsupported; Server and Client must be upgraded together.

## Consequences

- ingress TLVs and raw bytes never cross trust boundaries
- direct and load-balanced ingress produce the same internal address contract
- each Service explicitly controls its Local backend byte stream
- invalid internal framing rejects only that application stream
- deployments cannot roll Server and Client framing changes independently
