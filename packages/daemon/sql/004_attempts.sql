CREATE TABLE attempts (
  queue BLOB NOT NULL,
  envelope BLOB NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (queue, envelope)
) STRICT, WITHOUT ROWID;
