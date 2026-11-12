-- Stored envelopes and the tombstones an acknowledgment leaves. Every write
-- here runs inside a transaction mailbox/service or the sweep opened, beside
-- the quota change that must commit with it.

-- name: EnvelopeRecord :one
SELECT digest, deadline, size FROM envelopes
WHERE queue_id = ? AND envelope_id = ?;

-- name: Tombstone :one
SELECT digest, deadline FROM tombstones
WHERE queue_id = ? AND envelope_id = ?;

-- name: InsertEnvelope :exec
INSERT INTO envelopes (queue_id, envelope_id, digest, deadline, size,
                       ciphertext)
VALUES (?, ?, ?, ?, ?, ?);

-- name: LiveEnvelopes :many
SELECT envelope_id, deadline, ciphertext FROM envelopes
WHERE queue_id = sqlc.arg(queue_id) AND deadline >= sqlc.arg(now)
ORDER BY seq ASC LIMIT sqlc.arg(max);

-- name: DeleteEnvelope :exec
DELETE FROM envelopes WHERE queue_id = ? AND envelope_id = ?;

-- name: PutTombstone :exec
INSERT OR REPLACE INTO tombstones
  (queue_id, envelope_id, digest, deadline) VALUES (?, ?, ?, ?);

-- SUM over an integer column is cast because sqlc would type it as a float,
-- which the integer SQLite returns does not decode as.

-- name: ExpiredPerQueue :many
SELECT queue_id, CAST(SUM(size) AS INTEGER) AS bytes, COUNT(*) AS envelopes
FROM envelopes
WHERE deadline < sqlc.arg(now) GROUP BY queue_id;

-- name: DeleteExpiredEnvelopes :exec
DELETE FROM envelopes WHERE deadline < sqlc.arg(now);

-- name: StaleTombstones :one
SELECT COUNT(*) AS stale FROM tombstones WHERE deadline < sqlc.arg(now);

-- name: DeleteStaleTombstones :exec
DELETE FROM tombstones WHERE deadline < sqlc.arg(now);

-- name: EnvelopeSummary :one
SELECT COUNT(*) AS envelopes,
       CAST(COALESCE(SUM(size), 0) AS INTEGER) AS envelope_bytes
FROM envelopes
WHERE deadline >= sqlc.arg(now);

-- name: LiveTombstones :one
SELECT COUNT(*) AS tombstones
FROM tombstones
WHERE deadline >= sqlc.arg(now);
