# OMEGA-X v4.8 — mTLS capability admission gateway

## Trust boundary and protocol

This is an initial private control-plane transport, not a full peer-to-peer mesh.
It exposes exactly one request: admission of an Ed25519 CAPCTL envelope.
It never accepts shell commands, filesystem operations, arbitrary model weights,
or anonymous network registration.

The TLS server requires a trusted client certificate and a SHA-256 pin of its
leaf DER certificate mapped to the enrolled node ID. The signed CAPCTL node
ID must match that mapping. CAPCTL independently verifies signature, public
key pin, clock window, operator policy, and durable SQLite anti-replay state.
The client verifies CA, server SAN, TLS 1.3, and the server's pinned leaf
certificate before transmitting the envelope. Keep the TLS private key separate
from the CAPCTL Ed25519 signing key. TLS sessions and receipts do not establish
hardware attestation or trust in a compromised endpoint.

One request and one reply per connection. Each frame is a big-endian uint32
length followed by UTF-8 JSON, limited to 256 KiB. Duplicate JSON keys and
NaN/Infinity tokens are refused. Unknown operations fail closed.
The server accepts a bounded number of worker connections (8 by default,
maximum 32), an absolute socket/frame deadline, and a bounded listen backlog.
The deadline does not interrupt an already-running CAPCTL verification or DB
commit. A lost response may therefore follow successful admission; retry
with a fresh signed declaration rather than replaying the old one.

## Provisioning

Use an operator-managed private CA with proper certificate constraints.
Issue distinct serverAuth and clientAuth certificates; the server must have
a SAN matching the exact IP/DNS name used by the client.
Keep CA signing keys offline and all endpoint keys outside the repository,
with owner-only permissions (0600); the current loader supports unattended
unencrypted private key files. Provision on a private filesystem, not shared
Android storage. Obtain certificate fingerprints through a trusted channel.

    python3 -m atlas.mesh fingerprint /private/server.pem
    python3 -m atlas.mesh fingerprint /private/node.pem

Create pins.json as a JSON object mapping the client leaf DER SHA-256 fingerprint
to its enrolled CAPCTL node ID. One leaf pin per node. Reuse the existing
CAPCTL policy format, with the independently pinned Ed25519 public key and
operator limits. The SQLite DB parent must be owner-only (0700).

## Start and submit

From repository root:

    python3 -m atlas.mesh serve --ca /private/ca.pem \
      --cert /private/server.pem --key /private/server.key \
      --policy /private/policy.json --pins /private/pins.json \
      --db /private/replay.db --bind 127.0.0.1 --port 8443

Use an explicit assigned IPv4 address and --allow-network for a private
LAN/VPN deployment, with operator firewall rules; wildcard binds are refused.
Do not expose directly to the public Internet without additional controls.

Sign the current node declaration through tools/capctl.py and submit:

    python3 -m atlas.mesh submit --host 127.0.0.1 --port 8443 \
      --ca /private/ca.pem --cert /private/node.pem \
      --key /private/node.key --server-pin "$TRUSTED_SERVER_CERT_SHA256" \
      --envelope /private/envelope.json

ADMITTED means this signed declaration passed the gateway's checks at
the time of admission. The receipt is bound to node ID and issued_ns over
TLS; it is not an independently signed or durable capability snapshot.
There is no node discovery, dispatch, distributed lease, cluster membership
consensus, public Internet readiness, automatic certificate issuance/rotation,
revocation distribution, or persistent audit trail beyond replay state.
Rotate enrolled certificates by updating pins and restarting the gateway.
Use a private network and external traffic controls; continuous connection
floods can still exhaust bounded slots. No Android/VPS deployment is claimed.

## Verification

Linux Python 3.13.5 / OpenSSL 3.5.5: 26/26 focused tests (16 new mesh tests and
10 existing CAPCTL tests) passed in one run. Real TLS sockets, generated local
test CA and certificates, certificate identity pinning, hostname verification,
foreign CA, missing certificate, TLS 1.2 refusal, duplicate requests, expired
and tampered envelopes, malformed frames, connection saturation and timeout
recovery, and separate CLI server/client processes were exercised.
Python compilation passed for the focused checkout.
Complete repository regression remains blocked by DNS in the test runner.
No real S24, VPS, or cross-network certificate deployment was performed.

    python3 -m unittest discover -s tests -p test_mesh.py -v
    python3 -m unittest discover -s tests -p test_capctl.py -v
