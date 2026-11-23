# E20b — deterministic fault-injection model for distributed authority

The simulator validates the existing `atlas.distributed_authority.Authority`, `AuthorityGuard` and `GuardedCoordinator` using their public interfaces and a controlled etcd-v3-like RPC boundary. This is **not** a deployable etcd service, Raft implementation, independent consensus verification, TLS test or real physical fencing.

## Deterministic model

3/5/7 named members, disjoint connectivity partitions, node crash/recovery, majority gating before every linearizable read/transaction, one lock-serialized logical committed key-value history, version-zero bootstrap CAS and revision compare-and-swap transfer. A one-shot fault can lose the response **after** a successful commit, exercising the existing client's ambiguous-outcome policy. `trace_digest()` creates a SHA-256 fingerprint of a deterministic sequential schedule.

## Actual locally executed acceptance

```sh
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p test_quorum_simulation.py -v
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q atlas tools tests
```

13 E20b cases: CAS ownership, minority isolation, quorum loss/recovery, lost post-commit ACK, stale-grant revocation, guarded dispatch under partition/heal, 12 concurrent transfers, namespace isolation, cluster-ID mismatch, five-node failover, all 27 three-node member-state permutations, invalid partition rejection and deterministic trace. The **three independent** E20/E21/E22 local subset regression runs each passed 42/42 tests (13 E20 + 15 E21 + 14 E22); Python compileall passed. E21/E22 use controlled subprocess/adapters, **not physical SMB**. The local runner used a manually mirrored copy of the existing Authority API and was not a byte-identical full GitHub checkout; the new source/test are byte-identical to the local tested Git blobs.

Example fixed-nonce event trace SHA-256: `52bef993ba9210c1c6c5a15325d77ef2b04b80858db307cce8094aa4674b5769`, bootstrap revision 2, isolate old owner, transfer on majority revision 3.

## Engineering gates

E20b GATE-04=PASS_SIMULATION, GATE-05=SIMULATION_VERIFIED_PARTIAL, GATE-06/07=PARTIAL_SIMULATION, GATE-08=PASS for recorded local evidence. Global GATE-09=OPEN. In particular, the model serializes all commits in one in-memory ledger **by construction**: it cannot establish crash-consistency of physically separate etcd nodes, Raft liveness/durability, independent disk fault domains, TLS, host fencing, production recovery or RPO/RTO. It must never serve as a production authority.
