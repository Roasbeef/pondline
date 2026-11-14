-- The one piece of rendezvous state a daemon keeps (ADR-016): a row per
-- confirmation failure of a spoken-code pairing, keyed by the rendezvous
-- endpoint's text, with the time it was recorded. A failure may be a spent
-- guess at the code's words, so a daemon refuses codes at an endpoint once
-- enough of them fall inside the window. Rows hold an endpoint and a time
-- only, never a code, a word or a message.

-- name: RendezvousFailureCount :one
SELECT CAST(COUNT(*) AS INTEGER) AS total FROM rendezvous_failures
WHERE endpoint = sqlc.arg(endpoint) AND at > sqlc.arg(since);

-- name: PruneRendezvousFailures :exec
DELETE FROM rendezvous_failures WHERE at <= sqlc.arg(since);

-- name: InsertRendezvousFailure :exec
INSERT INTO rendezvous_failures (endpoint, at) VALUES (?, ?);

