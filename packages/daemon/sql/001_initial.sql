
CREATE TABLE meta (
  key TEXT NOT NULL PRIMARY KEY,
  value BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE relationships (
  contact BLOB NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  phase TEXT NOT NULL,
  description TEXT NOT NULL,
  inbox_queue BLOB NOT NULL UNIQUE,
  inbox BLOB NOT NULL,
  blob BLOB NOT NULL
) STRICT;

CREATE TABLE offers (
  invitation BLOB NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  phase TEXT NOT NULL,
  description TEXT NOT NULL,
  deadline INTEGER NOT NULL,
  inbox_queue BLOB NOT NULL UNIQUE,
  inbox BLOB NOT NULL,
  blob BLOB NOT NULL,
  file BLOB NOT NULL
) STRICT;

CREATE TABLE outbox (
  envelope BLOB NOT NULL PRIMARY KEY,
  contact BLOB NOT NULL,
  kind TEXT NOT NULL,
  message_id BLOB,
  route BLOB NOT NULL,
  padded BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'stored', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  receipt BLOB
) STRICT;

CREATE INDEX outbox_due ON outbox (status, next_attempt_at);

CREATE TABLE processed (
  queue BLOB NOT NULL,
  envelope BLOB NOT NULL,
  digest BLOB NOT NULL,
  outcome TEXT NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (queue, envelope)
) STRICT, WITHOUT ROWID;

CREATE TABLE deliveries (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  contact BLOB NOT NULL,
  message_id BLOB NOT NULL,
  content_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  in_reply_to BLOB,
  status TEXT NOT NULL
    CHECK (status IN ('ready', 'held', 'expired', 'consumed')),
  received_at INTEGER NOT NULL,
  UNIQUE (contact, message_id)
) STRICT;

CREATE TABLE sent_messages (
  message_id BLOB NOT NULL PRIMARY KEY,
  contact BLOB NOT NULL,
  state TEXT NOT NULL CHECK (
    state IN ('locally_queued', 'stored_by_mailbox', 'received_by_peer',
              'failed')
  )
) STRICT;

CREATE TABLE audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  contact BLOB NOT NULL,
  direction TEXT NOT NULL,
  message_id BLOB NOT NULL,
  content_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  at INTEGER NOT NULL
) STRICT;
