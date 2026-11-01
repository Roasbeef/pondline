//// A mailbox restored from a backup: the `Restore` fault class.
////
//// A mailbox operator who restores the database from a backup taken before
//// some acknowledgements brings those envelopes back: the same rows, under
//// the same identifiers, bytes and sequence numbers (so at the head of
//// their queues), with no tombstone, since the backup predates it. The
//// receiver already processed and acknowledged each of them, so all it can
//// do is acknowledge them again (ADR-010, addendum). A sender's retry that
//// lands after the tombstone's deadline passed is the same fault seen from
//// the receiver, with the row at the tail instead of the head.
////
//// The backup is kept by SQLite itself, in the mailbox's own database: a
//// trigger copies every envelope row the mailbox inserts into
//// `sim_backup`, inside the mailbox's own transaction, so a row that
//// rolled back was never backed up. A restore puts back every backed-up
//// envelope the mailbox has since tombstoned, which is a backup taken just
//// before each acknowledgement. It restores only those: nothing the
//// mailbox stored after a backup is lost, so the fault is exactly the
//// re-served envelope and not ADR-006's lost one.
////
//// Every statement runs on the harness's keeper connection at an op
//// boundary, when the VM is quiescent and no transaction of the mailbox is
//// open. A write that fails is a harness fault and panics.

import sim/tables
import sqlight.{type Connection}

/// Creates the backup table and the trigger that fills it. Runs once, on
/// the mailbox's freshly migrated store, before the mailbox node starts.
///
/// ## Examples
///
/// ```gleam
/// restore.install(keeper)
/// ```
pub fn install(keeper: Connection) -> Nil {
  let assert Ok(Nil) =
    sqlight.exec(
      "CREATE TABLE sim_backup (
         queue_id BLOB NOT NULL,
         envelope_id BLOB NOT NULL,
         seq INTEGER NOT NULL,
         digest BLOB NOT NULL,
         deadline INTEGER NOT NULL,
         size INTEGER NOT NULL,
         ciphertext BLOB NOT NULL,
         PRIMARY KEY (queue_id, envelope_id)
       );
       CREATE TRIGGER sim_backup_insert AFTER INSERT ON envelopes BEGIN
         INSERT OR IGNORE INTO sim_backup
           (queue_id, envelope_id, seq, digest, deadline, size, ciphertext)
         VALUES (NEW.queue_id, NEW.envelope_id, NEW.seq, NEW.digest,
                 NEW.deadline, NEW.size, NEW.ciphertext);
       END;",
      keeper,
    )
    as "the mailbox backup installs"

  Nil
}

/// Restores every backed-up envelope the mailbox has tombstoned since: the
/// row returns under its old sequence number, its tombstone goes, and its
/// bytes count against its queue again. Returns the `(queue, envelope)`
/// pairs it restored, so the runner can stop holding the mailbox to the
/// tombstones it removed.
///
/// ## Examples
///
/// ```gleam
/// restore.restore(keeper)
/// // -> [tables.Stored(queue:, envelope:)]
/// ```
pub fn restore(keeper: Connection) -> List(tables.Stored) {
  let restorable = tables.restorable(keeper)

  // The bytes are counted before the rows return, while the join still
  // selects them; then the rows, then the tombstones they replace.
  let assert Ok(Nil) =
    sqlight.exec(
      "BEGIN IMMEDIATE;
       UPDATE queues SET bytes_used = bytes_used + (
         SELECT COALESCE(SUM(b.size), 0) FROM sim_backup AS b
         JOIN tombstones AS t
           ON t.queue_id = b.queue_id AND t.envelope_id = b.envelope_id
         WHERE b.queue_id = queues.queue_id);
       INSERT INTO envelopes
         (seq, queue_id, envelope_id, digest, deadline, size, ciphertext)
       SELECT b.seq, b.queue_id, b.envelope_id, b.digest, b.deadline,
              b.size, b.ciphertext
       FROM sim_backup AS b
       JOIN tombstones AS t
         ON t.queue_id = b.queue_id AND t.envelope_id = b.envelope_id;
       DELETE FROM tombstones WHERE EXISTS (
         SELECT 1 FROM envelopes AS e
         WHERE e.queue_id = tombstones.queue_id
           AND e.envelope_id = tombstones.envelope_id);
       COMMIT;",
      keeper,
    )
    as "the mailbox restore applies"

  restorable
}
