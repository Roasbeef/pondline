CREATE TABLE rendezvous_failures (
  seq INTEGER PRIMARY KEY,
  endpoint TEXT NOT NULL,
  at INTEGER NOT NULL
) STRICT;

CREATE INDEX rendezvous_failures_by_endpoint
  ON rendezvous_failures (endpoint, at);
