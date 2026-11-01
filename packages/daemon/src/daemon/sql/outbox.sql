-- The outbox and the sent-message states the agent asks about. A row's bytes
-- are written once, by InsertOutbound or by CopyForRetransmit from another
-- committed row, and never from outside the store; every other statement
-- here moves a row's status, attempts or retransmit schedule.

-- name: InsertOutbound :exec
INSERT INTO outbox
  (envelope, contact, kind, message_id, route, padded, deadline, status,
   attempts, next_attempt_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?);

-- name: InsertSentMessage :exec
INSERT INTO sent_messages (message_id, contact, state)
VALUES (?, ?, 'locally_queued');

-- The source is aliased because sqlc reports an unqualified column of a
-- table that is both the target and the source as ambiguous, and the two
-- envelopes are named because positional parameters would both be called
-- envelope. Only a row whose schedule is still running is copied, so a copy
-- that returns no row lost a race.

-- name: CopyForRetransmit :many
INSERT INTO outbox
  (envelope, contact, kind, message_id, route, padded, deadline, status,
   attempts, next_attempt_at, retransmits)
SELECT sqlc.arg(fresh), replaced.contact, replaced.kind, replaced.message_id,
       replaced.route, replaced.padded, replaced.deadline, 'queued', 0,
       sqlc.arg(now), sqlc.arg(retransmits)
FROM outbox AS replaced
WHERE replaced.envelope = sqlc.arg(replaces)
  AND replaced.retransmit_at IS NOT NULL
RETURNING envelope;

-- name: EndSchedule :exec
UPDATE outbox SET retransmit_at = NULL WHERE envelope = ?;

-- name: EndMessageSchedules :exec
UPDATE outbox SET retransmit_at = NULL
WHERE contact = ? AND message_id = ? AND kind = 'application';

-- name: Due :many
SELECT envelope, route, padded, deadline, attempts FROM outbox
WHERE status = 'queued' AND next_attempt_at <= sqlc.arg(now)
ORDER BY rowid LIMIT sqlc.arg(max);

-- name: MarkStored :exec
UPDATE outbox SET status = 'stored', receipt = ?, retransmit_at = ?
WHERE envelope = ?;

-- name: MarkFailed :exec
UPDATE outbox SET status = 'failed' WHERE envelope = ?;

-- name: Reschedule :exec
UPDATE outbox SET attempts = ?, next_attempt_at = ?
WHERE envelope = ?;

-- name: RetransmitSchedule :one
SELECT kind, message_id, deadline, retransmits,
       EXISTS (SELECT 1 FROM sent_messages AS sent
               WHERE sent.message_id = outbox.message_id
                 AND sent.state = 'received_by_peer') AS receipted
FROM outbox WHERE envelope = ?;

-- name: DueRetransmits :many
SELECT envelope, contact, kind, message_id, deadline, retransmits
FROM outbox
WHERE retransmit_at IS NOT NULL AND retransmit_at <= sqlc.arg(now)
ORDER BY retransmit_at LIMIT sqlc.arg(max);

-- name: AdvanceMessage :exec
UPDATE sent_messages SET state = ?
WHERE state = 'locally_queued'
  AND message_id = (SELECT message_id FROM outbox WHERE envelope = ?);

-- name: MarkReceivedByPeer :exec
UPDATE sent_messages SET state = 'received_by_peer'
WHERE contact = ? AND message_id = ?;

-- name: PendingCount :one
SELECT COUNT(*) AS pending FROM outbox WHERE status = 'queued';
