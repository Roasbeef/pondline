-- Sealed invitations held for tickets (ADR-009). Every write here runs
-- inside a transaction mailbox/service or the sweep opened, beside the quota
-- change that must commit with it.

-- name: BlobRecord :one
SELECT queue_id, retrieve_hash, digest, deadline FROM blobs
WHERE blob_id = ?;

-- name: InsertBlob :exec
INSERT INTO blobs (blob_id, queue_id, retrieve_hash, digest, deadline, size,
                   sealed)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: LiveBlob :one
SELECT retrieve_hash, sealed FROM blobs
WHERE blob_id = sqlc.arg(blob_id) AND deadline >= sqlc.arg(now);

-- name: ExpiredBlobsPerQueue :many
SELECT queue_id, CAST(SUM(size) AS INTEGER) AS bytes, COUNT(*) AS blobs
FROM blobs
WHERE deadline < sqlc.arg(now) GROUP BY queue_id;

-- name: DeleteExpiredBlobs :exec
DELETE FROM blobs WHERE deadline < sqlc.arg(now);
