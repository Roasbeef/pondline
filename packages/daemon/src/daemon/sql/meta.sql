-- Daemon-wide values, such as the agent identifier, keyed by name.

-- name: MetaGet :one
SELECT value FROM meta WHERE key = ?;

-- name: MetaPut :exec
INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?);
