//// The seed decoder and the deterministic suite, which every run and every
//// replay rests on.

import gleam/bit_array
import gleam/list
import sim/rng
import sim/seed
import sim/suite

pub fn a_short_seed_enables_every_class_test() {
  let script = seed.decode(<<0>>)

  assert script.enabled == seed.classes()
  assert script.ops == []
}

pub fn the_mask_selects_classes_by_bit_test() {
  // Bits 0 and 7: daemon store faults and clock skew.
  let script = seed.decode(<<0, 0b1000_0001, 0>>)

  assert script.enabled == [seed.StoreDaemon, seed.Skew]
}

pub fn a_masked_op_is_an_honest_one_test() {
  // Op 15 is a skew, whose class is off here; argument 1 makes it an
  // advance of time.
  let script = seed.decode(<<0, 0, 0, 15, 1>>)

  assert script.ops == [seed.Advance(ms: 60)]
}

pub fn ops_stop_at_the_limit_test() {
  let ops = list.repeat(<<2, 0>>, seed.max_ops + 5) |> bit_array.concat
  let script = seed.decode(<<0, 0, 0, ops:bits>>)

  assert list.length(script.ops) == seed.max_ops
}

pub fn the_mode_byte_picks_a_configuration_test() {
  assert seed.decode(<<1>>).mode
    == seed.Mode(approval: seed.ByOperator, budget: 100)
  assert seed.decode(<<6>>).mode
    == seed.Mode(approval: seed.Automatic, budget: 2)
}

pub fn hex_round_trips_test() {
  assert seed.from_hex(seed.to_hex(<<0, 1, 171, 255>>))
    == Ok(<<0, 1, 171, 255>>)
}

pub fn two_suites_with_one_seed_draw_alike_test() {
  let first = suite.new(<<7>>, "a")
  let second = suite.new(<<7>>, "a")
  let other = suite.new(<<7>>, "b")

  assert first.random(16) == second.random(16)
  assert first.x25519_keypair() == second.x25519_keypair()
  assert first.random(16) != other.random(16)
}

pub fn the_fake_kem_and_signatures_agree_test() {
  let fake = suite.new(<<9>>, "a")
  let #(secret, public) = fake.kem_keypair()
  let assert Ok(#(shared, ciphertext)) = fake.kem_encapsulate(public)

  assert fake.kem_decapsulate(secret, ciphertext) == Ok(shared)
  assert bit_array.byte_size(public) == 1568

  let #(signing, verifying) = fake.mldsa_keypair()
  let assert Ok(signature) = fake.mldsa_sign(signing, <<"m">>)

  assert fake.mldsa_verify(verifying, <<"m">>, signature)
  assert !fake.mldsa_verify(verifying, <<"n">>, signature)
  assert bit_array.byte_size(signature) == 3309
}

pub fn the_generator_is_a_function_of_its_seed_test() {
  let #(first, _) = rng.bytes(rng.new(42), 8)
  let #(second, _) = rng.bytes(rng.new(42), 8)

  assert first == second
}
