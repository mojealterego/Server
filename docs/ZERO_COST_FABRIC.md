# OMEGA ZERO-COST STORAGE FABRIC — STORAGE-07a

Locally tested capacity planner and archive, not a provisioned cloud pool or live SMB filesystem. Zero-cost is policy, not a billing guarantee. Current writes are local only.

## Capacity inventory and planning

Run from repository root:
    python -m atlas.capacity_fabric probe-local --path /private/volume --host edge1
    python -m atlas.capacity_fabric probe-remote --alias enrolled --pool provider-account-identity
    python -m atlas.capacity_fabric capacity --policy /private/policy.json
    python -m atlas.capacity_fabric plan --policy /private/policy.json --bytes 1000000000
    python -m atlas.capacity_fabric verify --policy /private/policy.json --proposal /private/proposal.json

The remote probe executes bounded read-only rclone about ALIAS: --json. Missing finite total/free quotas fail closed; actual API requests may consume quota. Local statvfs measures available bytes. Host/device identity is not physical failure-domain evidence. Roots must be stable and operator-enrolled.

Policy schema (example numbers; replace with observations and current UTC epoch):
    {"schema":"omega.capacity.v1","copies":2,"chunk_bytes":16777216,"max_age_seconds":300,"pools":[{"id":"example","pool":"operator-enrolled-quota-id","domain":"operator-verified-failure-domain","kind":"local","limit_bytes":100000000000,"used_bytes":10000000000,"reserve_bytes":5000000000,"write_budget_bytes":10000000000,"read_budget_bytes":10000000000,"block_budget":1000,"observed_at":1800000000,"authorized":true,"zero_cost":true}]}

One pool cannot satisfy two copies. Use at least two independent failure domains. Give each shared underlying quota one unique pool ID; the probe does not prove identity or free eligibility. Confirm authorization, permitted API use, storage, network and request quotas before setting zero_cost=true. Reserve metadata/encryption overhead and external use. Cloud writes require a transactional ledger; concurrent proposals may overbook. Logical blocks are not provider API operations. R2 monthly storage/request budgets and B2 egress need separate evaluation.

Capacity is bounded by free bytes minus reserve and byte/block budgets. With r copies and per-domain available capacity C_i, a continuous upper bound P obeys sum(min(C_i,P)) >= rP. Indivisible chunks and greedy placement may reduce achievable space. A rejected greedy placement is not an infeasibility proof. A plan supports at most 65,536 blocks of 1..64 MiB. Independent feasibility verification reconstructs budgets, geometry, digest, freshness and distinct domains.

## Local actual data path
Supply existing private trusted local CAS roots mapped from pool IDs. Do not put CAS inside client-writable SMB shares or remote billable mounts.
    umask 077
    python -m atlas.pooled_archive ingest --source /private/input --policy /private/policy.json --proposal /private/proposal.json --roots /private/roots.json --host edge1 --manifest /private/archive.json
    python -m atlas.pooled_archive restore --manifest /private/archive.json --sha256 "$INDEPENDENT_MANIFEST_PIN" --roots /private/surviving-roots.json --host edge1 --dest /private/restored

Save the returned manifest_sha256 separately via an authenticated operator channel. CAS deduplicates verified blocks, reads back before publication, checks per-root flock and live reserve, and rejects redundant same-device aliases. Writes may leave unreferenced chunks on failure; no partial manifest or destination is published as complete. Restore checks block and whole-file hashes, uses one chunk at a time (at most 64 MiB plus overhead), and publishes no-overwrite with directory fsync. Archive limit 16,384 blocks (up to 1 TiB at 64 MiB). Extra staging space is required. Flows are offline, do not fence independent writers/mount changes, and do not implement distributed reservations, GC, ACL, writable POSIX semantics or live SMB failover. Local CAS content is plaintext; use private encrypted volumes. Hash pin is not a signature. Tmpfs is volatile.

## Advertised free quotas, checked 2026-11-20

| Provider | Nominal | Caveat |
|---|---:|---|
| OCI Always Free block | 200 GB total | Includes boot disks; eligibility/region/capacity |
| Google Drive | 15 GB | Shared with Gmail/Photos |
| Cloudflare R2 | 10 GB-month | Monthly and operation limits; paid overage |
| Backblaze B2 | 10 GB | Egress/operation constraints |
| OneDrive | 5 GB | Actual account quota |
| Dropbox | 2 GB | Actual account quota |
| Koofr | 10 GB | WebDAV; account quota |
| Filen | 10 GB advertised | Account eligibility and client |
| Proton Drive | Up to 5 GB | Welcome checklist may apply |
| TeraBox | Up to 1 TB/1024 GB advertised | Offer duration, official API access, quotas, file limits, terms and recovery unverified |

First six nominally total 242 GB before OS, reserves and redundancy. These are advertised quotas, not measured capacity of enrolled accounts. TeraBox is research-only, not admitted; use official authorized OAuth/Open Platform, never session-cookie scraping. Do not bypass provider limits with duplicate accounts, abuse Git hosting for archives, or enable billable automated writes without enforceable budget gates.

For immediate TB-scale storage without new subscriptions, pool owned USB/HDD/SSD volumes with mergerfs (mfs/minfreespace) on an authorized Linux host, export via existing Samba SMB3 encrypted service over private WireGuard/VPN. Never expose public port 445; signed SMB2 remains separate compatibility policy. Rclone Union is whole-file placement, not chunk striping, independent replication or concurrent POSIX semantics. Existing create_policy=all is a mirror; do not silently change it. Source-backed public AI model references with revisions/license/hash pins avoid duplicate local weights, not physical capacity. Unique/private data need durable storage.

Primary sources:
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- https://support.google.com/googleone/answer/9004014?hl=en
- https://developers.cloudflare.com/r2/pricing/
- https://www.backblaze.com/cloud-storage/pricing
- https://www.microsoft.com/pl-pl/microsoft-365/onedrive/free-online-cloud-storage/
- https://help.dropbox.com/plans/dropbox-basic-faq
- https://koofr.eu/
- https://docs.filen.io/docs/desktop/
- https://proton.me/support/more-storage-proton-drive
- https://www.terabox.com/cloud-storage-pricing-plans
- https://www.terabox.com/integrations/docs?lang=en
- https://www.terabox.com/integrations/docs/hindi
- https://rclone.org/commands/rclone_about/
- https://rclone.org/union/
- https://rclone.org/crypt/
- https://trapexit.github.io/mergerfs/latest/config/minfreespace/
- https://www.samba.org/samba/docs/current/man-html/smb.conf.5
