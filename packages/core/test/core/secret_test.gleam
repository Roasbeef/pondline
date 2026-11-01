import core/secret
import gleam/string
import qcheck

const property_count = 200

const property_seed = 19

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// A secret's rendering contains neither the bytes' list form nor their
/// Erlang binary form, and the bytes come back through `expose`.
pub fn inspect_never_shows_the_bytes_property_test() {
  use bytes <- property(qcheck.fixed_size_byte_aligned_bit_array(24))

  let hidden = secret.new(bytes)
  let rendered = string.inspect(hidden)

  assert secret.expose(hidden) == bytes
  assert secret.byte_size(hidden) == 24
  assert !string.contains(rendered, string.inspect(bytes))
  assert !string.contains(rendered, "<<")
}

/// A known secret does not show up in any rendering of itself or of a
/// value that holds it.
pub fn known_secret_is_not_rendered_test() {
  let hidden = secret.new(<<"hunter2-hunter2":utf8>>)

  assert !string.contains(string.inspect(hidden), "hunter2")
  assert !string.contains(string.inspect(Ok(hidden)), "hunter2")
  assert !string.contains(string.inspect([hidden]), "hunter2")
}

/// Two secrets are equal exactly when their bytes are.
pub fn equality_is_by_bytes_property_test() {
  use #(left, right) <- property(qcheck.tuple2(
    qcheck.fixed_size_byte_aligned_bit_array(4),
    qcheck.fixed_size_byte_aligned_bit_array(4),
  ))

  assert { secret.new(left) == secret.new(right) } == { left == right }
  assert secret.new(left) == secret.new(left)
}
