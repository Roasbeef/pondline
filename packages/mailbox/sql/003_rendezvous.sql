-- Rendezvous slots for pairing by a spoken code (ADR-016). A slot is named
-- by the identifier its opener chose and by the nameplate the mailbox drew,
-- is charged to the provisioning grant that opened it, and lives until
-- expires_at. Each of its four capabilities is kept only as its SHA-256
-- hash; the claimant's pair is NULL until the slot is claimed.
--
-- A nameplate is unique among stored slots. The open that draws one first
-- deletes every expired slot, so the only rows a draw can collide with are
-- live ones, and the index is a second guard behind the draw.

CREATE TABLE rendezvous (
  rendezvous_id BLOB NOT NULL PRIMARY KEY,
  nameplate INTEGER NOT NULL UNIQUE,
  grant_hash BLOB NOT NULL REFERENCES grants(capability_hash),
  opener_read_hash BLOB NOT NULL,
  opener_append_hash BLOB NOT NULL,
  claimant_read_hash BLOB,
  claimant_append_hash BLOB,
  lifetime INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX rendezvous_by_expiry ON rendezvous (expires_at);

CREATE INDEX rendezvous_by_grant ON rendezvous (grant_hash);

-- One side's messages, at most a fixed number per side, numbered by their
-- sender. side is 0 for the opener and 1 for the claimant. Messages go with
-- their slot through the cascade.

CREATE TABLE rendezvous_messages (
  rendezvous_id BLOB NOT NULL
    REFERENCES rendezvous(rendezvous_id) ON DELETE CASCADE,
  side INTEGER NOT NULL,
  message_index INTEGER NOT NULL,
  digest BLOB NOT NULL,
  body BLOB NOT NULL,
  PRIMARY KEY (rendezvous_id, side, message_index)
) STRICT, WITHOUT ROWID;
