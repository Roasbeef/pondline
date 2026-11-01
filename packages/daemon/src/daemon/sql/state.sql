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
