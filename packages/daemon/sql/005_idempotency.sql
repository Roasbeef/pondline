ALTER TABLE relationships ADD COLUMN invitation BLOB;

CREATE UNIQUE INDEX relationships_by_invitation ON relationships (invitation)
  WHERE invitation IS NOT NULL AND phase <> 'closed';

CREATE TABLE send_keys (
  contact BLOB NOT NULL,
  key TEXT NOT NULL,
  message_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (contact, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX send_keys_by_expiry ON send_keys (expires_at);
