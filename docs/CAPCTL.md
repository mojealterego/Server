# OMEGA-X CAPCTL — signed capability admission

This tool accepts one to eight node declarations and emits PHASESHIFT-compatible node JSON. It uses OpenSSL Ed25519, Python stdlib and an operator-owned SQLite replay database. No secrets or keys are committed.

## Enrollment and trust boundary

On each node (OpenSSL 3.x required):

    umask 077
    mkdir -p "$HOME/.omega-x"
    openssl genpkey -algorithm ED25519 -out "$HOME/.omega-x/cap-key.pem"
    chmod 600 "$HOME/.omega-x/cap-key.pem"
    openssl pkey -in "$HOME/.omega-x/cap-key.pem" -pubout -outform DER | base64 -w0

Transfer and verify the public key out of band before enrolling it. Never trust a public key solely because it accompanies an envelope. Each node needs a distinct key. The private key is currently an unencrypted PEM, protected by owner-only filesystem permissions; do not put it in Android shared storage. Run key generation only once; do not overwrite an enrolled key.

Create a private operator policy JSON mapping the node ID to these exact fields: public_key (base64 Ed25519 SPKI DER from enrollment), trust (local/trusted/untrusted), priority, max_ram_mb, min_headroom_mb, max_disk_bytes, capabilities (array of allowed engines), models (array of allowed model IDs). Choose ceilings and trust independently of the node. The policy, replay DB and accepted nodes output are operator-controlled.

The node declaration must contain exactly id, ram_available_mb, ram_headroom_mb, disk_free_bytes, thermal_c, capabilities and models. These are operator or agent supplied measurements/declarations; unknown temperature is rejected. Use IDs matching the planner catalog, not file paths. Trust and priority are assigned by policy, never by the signer.

## Admission and planning

On the node, sign a fresh declaration stored in node.json:

    python3 tools/capctl.py sign --node node.json --key "$HOME/.omega-x/cap-key.pem" > signed.json

Deliver signed.json over an authenticated transport. The signature provides integrity but not confidentiality.

On the planner host, with enrolled policy.json:

    mkdir -p "$HOME/.omega-cap"
    chmod 700 "$HOME/.omega-cap"
    python3 tools/capctl.py admit --envelopes signed.json --policy policy.json --db "$HOME/.omega-cap/replay.sqlite" > "$HOME/.omega-cap/nodes.json" &&
    python3 tools/phasectl.py compile --tasks examples/phase_tasks.json --nodes "$HOME/.omega-cap/nodes.json" --catalog examples/phase_catalog.json --out "$HOME/.omega-cap/plan.json"

Use real task/catalog data matching your enrolled models. Admission is a batch transaction; all nodes must pass. Default max age is 120 seconds, configurable 1–300 seconds; at most 30 seconds of future clock skew. Strictly increasing issued_ns per node survives process restarts; clock rollback requires a fresh timestamp above the last accepted value. Concurrent duplicate messages cannot both be accepted against the same database. A failed output write after a committed admission consumes that declaration; sign a new one.

## Limits and evidence

This is an optional pre-planning gate, not automatic enforcement in the legacy planner or LeaseStore. Plan input must be refreshed before use; output does not preserve an active freshness lease. Authenticity is not physical truth: remote nodes can still lie within operator ceilings, and local telemetry, hardware attestation, authenticated transport, revocation/rotation workflow and distributed replay coordination remain open. Keep database, policy, outputs and their containing directories under exclusive operator control. Do not reset replay state casually.

Focused host verification (Linux, Python 3.13, OpenSSL 3.5.5): 10 tests passed, including real signing, tampering, key substitution, policy limits, timestamp bounds, replay after reopen, duplicate batch, concurrent replay and transaction rollback. Python compilation passed. The full existing repository could not be cloned in the test container due to DNS; full suite, Android and VPS validation were not performed in this change. Existing v4.3 reports are historical.

    python3 -m unittest discover -s tests -p test_capctl.py -v
