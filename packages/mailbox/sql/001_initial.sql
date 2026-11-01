
CREATE TABLE grants (
  capability_hash BLOB NOT NULL PRIMARY KEY,
  allowance INTEGER NOT NULL,
  queues_used INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE queues (
  queue_id BLOB NOT NULL PRIMARY KEY,
  read_hash BLOB NOT NULL,
  append_hash BLOB NOT NULL,
  admin_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  bytes_used INTEGER NOT NULL,
  capacity INTEGER NOT NULL
) STRICT;

CREATE TABLE envelopes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  queue_id BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
  envelope_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  size INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  UNIQUE (queue_id, envelope_id)
) STRICT;

CREATE INDEX envelopes_by_deadline ON envelopes (deadline);

CREATE TABLE tombstones (
  queue_id BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
  envelope_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  PRIMARY KEY (queue_id, envelope_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX tombstones_by_deadline ON tombstones (deadline);
