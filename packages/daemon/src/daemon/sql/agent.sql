-- What the local API reads for the agent and the operator: ready deliveries,
-- consumption, sent-message states and the audit log. An optional contact is
-- written `(contact = sqlc.narg(contact) OR sqlc.narg(contact) IS NULL)`,
-- with the comparison first, because sqlc types the parameter from the first
-- place it appears and cannot type it from `IS NULL`.

-- name: ReadyDeliveries :many
SELECT message_id, contact, content_type, payload, in_reply_to,
       received_at
FROM deliveries
WHERE status = 'ready'
  AND (contact = sqlc.narg(contact) OR sqlc.narg(contact) IS NULL)
ORDER BY seq LIMIT sqlc.arg(max);

-- name: Consume :many
UPDATE deliveries SET status = 'consumed'
WHERE message_id = ? AND status = 'ready'
RETURNING seq;

-- name: SentState :one
SELECT state FROM sent_messages WHERE message_id = ?;

-- name: AuditEntries :many
SELECT contact, direction, message_id, content_type, payload, at
FROM audit
WHERE (contact = sqlc.narg(contact) OR sqlc.narg(contact) IS NULL)
ORDER BY seq DESC LIMIT sqlc.arg(max);
