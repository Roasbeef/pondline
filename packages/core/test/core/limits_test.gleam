import core/limits
import core/ticket
import gleam/list
import qcheck

const property_count = 500

const property_seed = 7

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// The padded size always holds the ciphertext, is one of the advertised
/// buckets, and is the smallest bucket that does; past the largest bucket
/// there is no padded size at all.
pub fn padded_size_is_the_smallest_holding_bucket_property_test() {
  use size <- property(qcheck.bounded_int(0, limits.max_ciphertext_bytes * 2))

  case limits.padded_size(size) {
    Ok(bucket) -> {
      assert size <= bucket
      assert list.contains(limits.padding_buckets, bucket)
      assert list.all(limits.padding_buckets, fn(other) {
        other < size || other >= bucket
      })
    }
    Error(Nil) -> {
      assert size > limits.max_ciphertext_bytes
    }
  }
}

/// The largest bucket is the stored-ciphertext limit, so padding never admits
/// a ciphertext the mailbox would refuse, nor refuses one it would store.
pub fn the_largest_bucket_is_the_ciphertext_limit_test() {
  assert list.last(limits.padding_buckets) == Ok(limits.max_ciphertext_bytes)
}

/// A sealed invitation of the largest size fits the mailbox's blob bound,
/// and the longest ticket fits the decoder's text bound (ADR-009).
pub fn the_ticket_bounds_hold_the_largest_ticket_and_blob_test() {
  assert limits.max_ticket_blob_bytes
    >= limits.max_invitation_bytes + ticket.blob_overhead_bytes
  assert limits.max_ticket_bytes >= 130
}
