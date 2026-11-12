-- Queues: their capability hashes and their byte quota. A queue's
-- envelopes and tombstones go with it through the foreign keys' cascade.

-- name: QueueById :one
SELECT read_hash, append_hash, admin_hash, created_at, bytes_used,
       capacity
FROM queues WHERE queue_id = ?;

-- name: InsertQueue :exec
INSERT INTO queues (queue_id, read_hash, append_hash, admin_hash,
                    created_at, bytes_used, capacity)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DeleteQueue :exec
DELETE FROM queues WHERE queue_id = ?;

-- name: AdjustBytes :exec
UPDATE queues SET bytes_used = bytes_used + sqlc.arg(delta)
WHERE queue_id = sqlc.arg(queue_id);

-- name: QueueSummary :one
SELECT COUNT(*) AS queues,
       CAST(COALESCE(SUM(bytes_used), 0) AS INTEGER) AS bytes_used,
       CAST(COALESCE(SUM(capacity), 0) AS INTEGER) AS capacity_total
FROM queues;
