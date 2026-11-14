-- Rendezvous slots and their messages (ADR-016). Every read that serves a
-- request filters on expires_at, so a slot is invisible from the instant it
-- expires whether or not the sweep has run. Every write runs inside a
-- transaction mailbox/service or the sweep opened.

-- name: RendezvousById :one
SELECT rendezvous_id, nameplate, grant_hash, opener_read_hash,
       opener_append_hash, claimant_read_hash, claimant_append_hash,
       lifetime, expires_at
FROM rendezvous
WHERE rendezvous_id = sqlc.arg(rendezvous_id)
  AND expires_at >= sqlc.arg(now);

-- name: RendezvousByNameplate :one
SELECT rendezvous_id, nameplate, grant_hash, opener_read_hash,
       opener_append_hash, claimant_read_hash, claimant_append_hash,
       lifetime, expires_at
FROM rendezvous
WHERE nameplate = sqlc.arg(nameplate) AND expires_at >= sqlc.arg(now);

-- name: LiveRendezvous :one
SELECT COUNT(*) AS live FROM rendezvous WHERE expires_at >= sqlc.arg(now);

-- name: LiveRendezvousOfGrant :one
SELECT COUNT(*) AS held FROM rendezvous
WHERE grant_hash = sqlc.arg(grant_hash) AND expires_at >= sqlc.arg(now);

-- name: NameplateTaken :one
SELECT COUNT(*) AS taken FROM rendezvous WHERE nameplate = ?;

-- name: InsertRendezvous :exec
INSERT INTO rendezvous (rendezvous_id, nameplate, grant_hash,
                        opener_read_hash, opener_append_hash, lifetime,
                        expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- The IS NULL guard makes the first claim stand in the statement itself,
-- behind the service's own check.

-- name: ClaimRendezvous :exec
UPDATE rendezvous
SET claimant_read_hash = sqlc.arg(read_hash),
    claimant_append_hash = sqlc.arg(append_hash),
    expires_at = sqlc.arg(expires_at)
WHERE rendezvous_id = sqlc.arg(rendezvous_id)
  AND claimant_read_hash IS NULL;

-- name: DeleteRendezvous :exec
DELETE FROM rendezvous WHERE rendezvous_id = ?;

-- name: RendezvousMessageDigest :one
SELECT digest FROM rendezvous_messages
WHERE rendezvous_id = ? AND side = ? AND message_index = ?;

-- name: InsertRendezvousMessage :exec
INSERT INTO rendezvous_messages (rendezvous_id, side, message_index, digest,
                                 body)
VALUES (?, ?, ?, ?, ?);

-- name: RendezvousMessagesAfter :many
SELECT message_index, body FROM rendezvous_messages
WHERE rendezvous_id = sqlc.arg(rendezvous_id)
  AND side = sqlc.arg(side)
  AND message_index > sqlc.arg(after)
ORDER BY message_index ASC;

-- name: ExpiredRendezvous :one
SELECT COUNT(*) AS expired FROM rendezvous WHERE expires_at < sqlc.arg(now);

-- name: DeleteExpiredRendezvous :exec
DELETE FROM rendezvous WHERE expires_at < sqlc.arg(now);
