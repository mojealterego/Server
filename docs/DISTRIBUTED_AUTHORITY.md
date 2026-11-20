# Compute v5.4b (increment) — operator-fenced etcd authority

The registry implements compare-and-swap ownership of a non-expiring etcd
key (`/omega/authority/v1/<namespace>`). An etcd modification revision is
its fencing generation. Bootstrap compares key version to zero; transfer
compares the previous modification revision and requires explicit old-host
fencing and latest-checkpoint confirmations. The grant binds a coordinator
ID, independent checkpoint SHA-256 and a unique nonce. No lease expires or
key is deleted by this client. A lost transaction reply is ambiguous:
inspect `status` through the same trusted cluster, do not blindly retry.

Provision an independently managed, TLS-protected etcd v3 cluster with
quorum, client authentication and RBAC restricting the operator to this
namespace. Use a distinct read-only identity for dispatch checks. Pin the
cluster ID and enroll the CA/endpoint independently; never repoint the
endpoint or restore/reset the etcd cluster without an explicit recovery
procedure. The cluster ID is checked before mutation and in the reply;
this does not protect against a trusted endpoint switching clusters in
between requests. No plaintext HTTP, redirects or proxy discovery.

    python3 -m atlas.distributed_authority --endpoint https://etcd.example:2379 \
      --ca /private/ca.pem --cert /private/operator.pem --key /private/operator.key \
      --cluster-id "$ETCD_CLUSTER_ID" --namespace production status

Use the same global arguments followed by `bootstrap --node node-a
--checkpoint-sha256 "$PIN" --confirm-empty` only after verifying that no
existing coordinator operates in the namespace. For handover, first stop
and physically/administratively fence all old writers; create or restore
the latest acknowledged checkpoint according to HA_CONTROL_PLANE.md. Use
`transfer --revision "$OLD_REVISION" --node node-b --checkpoint-sha256
"$PIN" --confirm-fenced --confirm-latest`. Save the returned grant.

Optional dispatch admission integration: add `--distributed-authority-config
/private/authority.json` to the existing `dispatch serve` arguments. This
file is an operator-managed JSON object with exactly these keys: `endpoint`,
`ca`, `cert`, `key`, `namespace`, `cluster_id`, `grant`. The `grant` member
contains the entire issued JSON grant (node, checkpoint_sha256, nonce,
revision). Use the dedicated read-only client identity. The registry is
checked before local coordinator initialization and before each admitted
request; unreachable, changed or absent grants reject admission. Maintain
same-host flock and SQLite checkpoints. Without the new flag, legacy
same-host mode is unchanged; do not mix modes for one authority namespace.

This is NOT an automatic distributed lease, a transaction spanning SQLite
and etcd, a physical fence, or live state replication. In-flight requests
can outlive an admission check. Direct LeaseStore callers and unmodified
entry points bypass it. Operators must fence those writers before transfer,
verify the actual checkpoint pin separately, and prohibit destructive
etcd administration while operating. Quorum-loss, snapshot rollback,
partition/TOCTOU, cross-host service integration and zero-RPO evidence
remain open. No production HA certification is claimed.

Protocol reference: https://etcd.io/docs/v3.6/dev-guide/api_grpc_gateway/

## Admission hardening

The range response must include a valid header revision, a consistent
count if present, no pagination, and a modification revision no greater
than the reported cluster revision. A successfully observed absent or
different grant irreversibly revokes the running guard. A stale concurrent
observation cannot clear that revocation. Restart only with an independently
verified current grant after investigation. A transient transport or malformed
response denies the request without deciding ownership. This latch is
process-local; it cannot detect a rollback never observed by this process
and does not fence in-flight side effects or survive restart. All previous
operator fencing and latest-state requirements still apply.
