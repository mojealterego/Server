# E17a: owner-authorized edge node enrollment

**Implemented scope:** single-host, opt-in identity admission for an edge node.
It does **not** launch a network listener, connect to a device, attest hardware
properties, measure real free bytes or establish an independent failure domain.

An operator signs a canonical `omega.edge.grant.v1` with Ed25519, pinning the
node key, owner, tenant, claimed domain, byte ceiling and short validity window
(<=31 days). The node proves possession of the enrolled private key by signing
a fresh, one-time 256-bit challenge bound to the full grant digest. The
operator public key is pinned in a private SQLite registry. Signatures,
validity window, epoch, replay state and duplicate identities fail closed.
Revocation is persistent and cannot be silently undone by a new grant. Epoch
fencing uses a **single local SQLite authority**, not etcd consensus.

The trust verdict is deliberately:
`OPERATOR_AUTHORIZED_NOT_PHYSICALLY_ATTESTED`. A purported `domain_claim`
is an operator declaration, **not proof that two devices have separate disks,
providers, administrators or power circuits**. E15's physical failure-domain
qualification is unaffected.

For actual data-plane enrollment next steps require: authenticated mTLS/VPN,
node challenge exchange with narrow agent identities, E13 quota reservations,
encrypted E14 transport, rate limits, device eviction, revoked key propagation,
privacy/tenant boundaries and cross-device recovery drills. No endpoint or
credentials are auto-created by this library.

**Acceptance:** 11 local tests involving actual Ed25519 signatures, forged
claims, possession, expiry, replay, revocation and stale epoch. No physical
connectivity, transfer throughput or cloud capacity measurements.
