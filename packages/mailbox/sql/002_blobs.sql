-- Sealed invitations held for tickets (ADR-009). A blob is named by its
-- locator, charged to the queue that stored it, and goes with that queue
-- through the foreign key's cascade. The retrieve capability is kept only
-- as its SHA-256 hash, like every other capability in this file.

CREATE TABLE blobs (
  blob_id BLOB NOT NULL PRIMARY KEY,
  queue_id BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
  retrieve_hash BLOB NOT NULL,
  digest BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  size INTEGER NOT NULL,
  sealed BLOB NOT NULL
) STRICT;

CREATE INDEX blobs_by_deadline ON blobs (deadline);
