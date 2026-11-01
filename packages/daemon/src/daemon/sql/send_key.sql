-- The idempotency keys of sends (ADR-011): which message a caller's key on a
-- relationship produced, and a digest of the request it named, so a retry
-- with the same key answers with the first message and a reuse for another
-- message is refused. A key is remembered for a message's retention and
-- pruned after it, in the transaction that stores the next key.

-- name: SendByKey :one
SELECT message_id, digest FROM send_keys
WHERE contact = sqlc.arg(contact) AND key = sqlc.arg(key)
  AND expires_at >= sqlc.arg(now);

-- name: PruneSendKeys :exec
DELETE FROM send_keys WHERE expires_at < sqlc.arg(now);

-- name: PutSendKey :exec
INSERT INTO send_keys (contact, key, message_id, digest, expires_at)
VALUES (?, ?, ?, ?, ?);
