# Compute v5.5b — bounded offline placement optimization

Explore up to eight deterministic node-priority variants using existing PHASESHIFT. Verify baseline and each candidate independently; bind feasible schedule back to original inputs and verify again. Preserve task recipes, trust, resources, policy, slots, settings, verified failure coverage and primary/already verified N-1 makespan. Each scenario uses original max_states, limited to 20,000; not a global optimality proof.

Profile schema:
    {"schema":"omega.workload.profile.v1","input_sha256":"<baseline input pin>","records":[{"task":"<task id>","node":"<node id>","observed_at":<UTC Unix seconds>,"samples_ms":[<10..100 integer samples>]}]}

Use equivalent real measurements on nominated hardware. CLI verifies baseline fingerprint, separately supplied profile digest, freshness, unique task/node keys and sample bounds. Objective sums per-stage nearest-rank p95 values for primary assignments; NOT measured workflow end-to-end p95. Candidate requires complete fresh coverage and strict improvement at least configured threshold (default 500 basis points); otherwise keep baseline.

    python -m atlas.workload_opt --baseline /private/plan.json --tasks /private/tasks.json --nodes /private/nodes.json --catalog /private/catalog.json --profile /private/profile.json --profile-sha256 "$TRUSTED_PROFILE_PIN" > /private/proposal.json

Returned plan compatible with existing verifier. No runtime activation, autonomous failover, real collection, source rewriting or deployment. Operator pin is integrity data, not device attestation. Use existing fenced migration path rather than swapping running lease authority.
