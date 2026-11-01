-- The relationships and offers: their snapshot blobs, the plain columns the
-- shell finds work by, and the inboxes the fetchers and the provisioner read.
-- daemon/store runs every write here inside the commit that owns it, and a
-- state update names the version it read, so an update that returns no row
-- lost a race (ADR-007 has how this file becomes daemon/sql).

-- name: InsertRelationship :exec
INSERT INTO relationships
  (contact, version, phase, description, inbox_queue, inbox, blob)
VALUES (?, 1, ?, ?, ?, ?, ?);

-- name: UpdateRelationship :many
UPDATE relationships
SET version = version + 1, phase = ?, blob = ?
WHERE contact = ? AND version = ?
RETURNING version;

-- name: InsertOffer :exec
INSERT INTO offers
  (invitation, version, phase, description, deadline, inbox_queue, inbox,
   blob, file)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateOffer :many
UPDATE offers
SET version = version + 1, phase = ?, blob = ?
WHERE invitation = ? AND version = ?
RETURNING version;

-- name: RelationshipByContact :one
SELECT version, description, blob FROM relationships WHERE contact = ?;

-- name: RelationshipByQueue :one
SELECT version, description, blob FROM relationships WHERE inbox_queue = ?;

-- name: Relationships :many
SELECT version, description, blob FROM relationships ORDER BY rowid;

-- name: OfferByQueue :one
SELECT version, description, blob FROM offers WHERE inbox_queue = ?;

-- name: ExpirableOffers :many
SELECT version, description, blob FROM offers
WHERE phase IN ('provisioning', 'open') AND deadline < sqlc.arg(now);

-- name: InvitationFile :one
SELECT phase, file FROM offers WHERE invitation = ?;

-- name: LiveInboxes :many
SELECT inbox FROM offers WHERE phase = 'open'
UNION ALL
SELECT inbox FROM relationships
WHERE phase IN ('awaiting', 'pending', 'active');

-- name: PendingInboxes :many
SELECT inbox FROM offers WHERE phase = 'provisioning'
UNION ALL
SELECT inbox FROM relationships WHERE phase = 'joining';

-- The inboxes nothing fetches any more whose committed envelopes are not all
-- acknowledged yet: a relationship that closed, or an offer that was
-- consumed or expired, between a commit and the acknowledgement that should
-- have followed it, a daemon restart included. The fetch manager gives each a
-- fetcher that acknowledges them and stops, so nothing committed is left on
-- the mailbox until retention.

-- name: DrainingInboxes :many
SELECT inbox FROM relationships AS r
WHERE r.phase = 'closed'
  AND EXISTS (SELECT 1 FROM processed AS p
              WHERE p.queue = r.inbox_queue AND p.acked = 0)
UNION ALL
SELECT inbox FROM offers AS o
WHERE o.phase IN ('consumed', 'expired')
  AND EXISTS (SELECT 1 FROM processed AS p
              WHERE p.queue = o.inbox_queue AND p.acked = 0);
