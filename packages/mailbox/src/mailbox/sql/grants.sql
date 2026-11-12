-- Provisioning grants, stored under the SHA-256 hash of their capability and
-- never under the capability itself (ADR-007 has how this file becomes
-- mailbox/sql).

-- name: InsertGrant :exec
INSERT INTO grants (capability_hash, allowance) VALUES (?, ?);

-- name: GrantByHash :one
SELECT capability_hash, allowance, queues_used FROM grants
WHERE capability_hash = ?;

-- name: UseGrant :exec
UPDATE grants SET queues_used = queues_used + 1
WHERE capability_hash = ?;

-- name: GrantSummary :one
SELECT COUNT(*) AS grants,
       CAST(COALESCE(SUM(allowance), 0) AS INTEGER) AS allowance_total,
       CAST(COALESCE(SUM(queues_used), 0) AS INTEGER) AS queues_used_total
FROM grants;
