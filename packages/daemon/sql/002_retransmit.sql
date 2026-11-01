
ALTER TABLE outbox ADD COLUMN retransmits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE outbox ADD COLUMN retransmit_at INTEGER;

CREATE INDEX outbox_retransmit ON outbox (retransmit_at)
  WHERE retransmit_at IS NOT NULL;

CREATE TABLE fingerprints (
  contact BLOB NOT NULL,
  digest BLOB NOT NULL,
  message_id BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  receipts INTEGER NOT NULL,
  PRIMARY KEY (contact, digest)
) STRICT, WITHOUT ROWID;

CREATE INDEX fingerprints_by_expiry ON fingerprints (expires_at);
