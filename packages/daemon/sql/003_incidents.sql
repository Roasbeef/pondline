CREATE TABLE incidents (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('repeated_message', 'quarantined')),
  queue BLOB NOT NULL,
  envelope BLOB NOT NULL,
  contact BLOB,
  message_id BLOB,
  attempts INTEGER,
  at INTEGER NOT NULL
) STRICT;
