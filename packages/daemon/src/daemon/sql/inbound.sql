-- What the daemon keeps of the envelopes it received: the processed log a
-- fetcher acknowledges from, the ratchet-message fingerprints that answer a
-- retransmit with its receipt (ADR-006), and the deliveries and audit rows a
-- commit writes for the agent.

-- name: PutProcessed :exec
INSERT OR REPLACE INTO processed
  (queue, envelope, digest, outcome, acked)
VALUES (?, ?, ?, ?, 0);

-- name: ProcessedDigest :one
SELECT digest FROM processed WHERE queue = ? AND envelope = ?;

-- name: Unacked :many
SELECT envelope FROM processed
WHERE queue = sqlc.arg(queue) AND acked = 0 LIMIT sqlc.arg(max);

-- name: MarkAcked :exec
UPDATE processed SET acked = 1 WHERE queue = ? AND envelope = ?;

-- name: PutFingerprint :exec
INSERT OR REPLACE INTO fingerprints
  (contact, digest, message_id, expires_at, receipts)
VALUES (?, ?, ?, ?, ?);

-- name: PruneFingerprints :exec
DELETE FROM fingerprints WHERE expires_at < sqlc.arg(now);

-- name: Fingerprint :one
SELECT message_id, expires_at, receipts FROM fingerprints
WHERE contact = ? AND digest = ?;

-- name: InsertDelivery :exec
INSERT INTO deliveries
  (contact, message_id, content_type, payload, in_reply_to, status,
   received_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ReleaseDelivery :exec
UPDATE deliveries SET status = 'ready'
WHERE contact = ? AND message_id = ? AND status = 'held';

-- name: InsertAudit :exec
INSERT INTO audit
  (contact, direction, message_id, content_type, payload, at)
VALUES (?, ?, ?, ?, ?, ?);

-- Whether a relationship already stored a message under an identifier: the
-- history the core's receive is told (ADR-010).

-- name: DeliveryOf :one
SELECT seq FROM deliveries WHERE contact = ? AND message_id = ?;

-- How many times an envelope was handed to the core without its outcome
-- committing (ADR-010). The count is written in a transaction of its own
-- before the envelope is processed, so a crash while processing it counts
-- too, and the Processed row that settles the envelope clears it.

-- name: CountAttempt :one
INSERT INTO attempts (queue, envelope, count) VALUES (?, ?, 1)
ON CONFLICT (queue, envelope) DO UPDATE SET count = count + 1
RETURNING count;

-- name: ClearAttempts :exec
DELETE FROM attempts WHERE queue = ? AND envelope = ?;
