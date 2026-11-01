-- What the daemon tells its operator about envelopes it set aside without
-- delivering them (ADR-010): an authenticated message that repeated an
-- identifier, and an envelope quarantined after failing too often. Rows hold
-- identifiers and counts only, never a payload.

-- name: InsertIncident :exec
INSERT INTO incidents
  (kind, queue, envelope, contact, message_id, attempts, at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: Incidents :many
SELECT kind, queue, envelope, contact, message_id, attempts, at
FROM incidents
ORDER BY seq DESC LIMIT sqlc.arg(max);

-- name: IncidentCount :one
SELECT CAST(COUNT(*) AS INTEGER) AS total FROM incidents;
