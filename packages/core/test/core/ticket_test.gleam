//// The ticket's text codec, its derivations and the sealed blob
//// (ADR-009), over the fake suite. `packages/primitives` repeats the blob
//// checks over the real ChaCha20-Poly1305.

import core/capability
import core/codex32
import core/crypto/fake_suite
import core/endpoint.{type Endpoint, Loopback, Onion}
import core/id
import core/secret
import core/ticket.{type Ticket}
import gleam/bit_array
import gleam/list
import gleam/string
import qcheck

/// How many values each property is checked over, and its fixed seed.
const property_count = 200

const property_seed = 109

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

// ------------------------------------------------------------- generators

fn port(number: Int) -> endpoint.Port {
  let assert Ok(port) = endpoint.port(number)
  port
}

/// A v3 onion address from a 32-byte key and a 2-byte checksum; the
/// version byte is always 3.
fn onion_from(key: BitArray, checksum: BitArray) -> endpoint.OnionAddress {
  let assert Ok(address) =
    endpoint.onion_from_bytes(<<key:bits, checksum:bits, 3>>)
  address
}

/// An endpoint, drawn as an index so a failure shrinks toward the loopback
/// one, the simpler format.
fn endpoints() -> qcheck.Generator(Endpoint) {
  qcheck.map3(
    qcheck.bounded_int(0, 1),
    qcheck.fixed_size_byte_aligned_bit_array(34),
    qcheck.bounded_int(1, 65_535),
    fn(kind, bytes, number) {
      let assert <<key:bytes-size(32), checksum:bytes-size(2)>> = bytes

      case kind {
        0 -> Loopback(port(number))
        _ -> Onion(onion_from(key, checksum), port(number))
      }
    },
  )
}

fn tickets() -> qcheck.Generator(Ticket) {
  qcheck.map2(
    endpoints(),
    qcheck.fixed_size_byte_aligned_bit_array(ticket.secret_bytes),
    fn(mailbox, secret) {
      let assert Ok(made) = ticket.from_parts(mailbox, secret)
      made
    },
  )
}

fn text(made: Ticket) -> String {
  let assert Ok(text) = bit_array.to_string(secret.expose(ticket.encode(made)))
  text
}

fn onion_ticket() -> Ticket {
  let address = onion_from(<<7:256>>, <<1, 2>>)
  let assert Ok(made) = ticket.from_parts(Onion(address, port(80)), <<9:256>>)
  made
}

fn loopback_ticket() -> Ticket {
  let assert Ok(made) = ticket.from_parts(Loopback(port(4100)), <<5:256>>)
  made
}

/// A checksummed string over arbitrary data symbols, so the decoder's
/// strictness is tested past the checksum.
fn checksummed(data: List(Int)) -> String {
  "rw1"
  <> codex32.from_symbols(data)
  <> codex32.from_symbols(codex32.checksum(ticket.prefix, data))
}

/// The data symbols of a valid ticket, without its checksum.
fn data_of(made: Ticket) -> List(Int) {
  let assert Ok(symbols) = codex32.to_symbols(string.drop_start(text(made), 3))
  list.take(symbols, list.length(symbols) - codex32.checksum_symbols)
}

// ------------------------------------------------------------------- text

/// Every ticket decodes to itself.
pub fn a_ticket_round_trips_test() {
  property(tickets(), fn(made) {
    let assert Ok(back) = ticket.decode(text(made))

    assert back == made
    assert ticket.endpoint(back) == ticket.endpoint(made)
  })
}

/// The two formats have fixed lengths: 130 characters for an onion
/// mailbox and 74 for a loopback one, both under the decoder's bound.
pub fn tickets_have_their_documented_lengths_test() {
  assert string.length(text(onion_ticket())) == 130
  assert string.length(text(loopback_ticket())) == 74
  assert string.starts_with(text(onion_ticket()), "rw1q")
  assert string.starts_with(text(loopback_ticket()), "rw1p")
}

/// Every single-character substitution, anywhere after the prefix, is
/// caught by the checksum.
pub fn the_checksum_catches_every_single_substitution_test() {
  let original = text(onion_ticket())
  let characters = string.to_graphemes(original)

  list.index_map(characters, fn(character, position) {
    use <- skip_prefix(position)

    codex32.alphabet
    |> string.to_graphemes
    |> list.filter(fn(other) { other != character })
    |> list.each(fn(other) {
      let mistyped = replace_at(characters, position, other)
      assert ticket.decode(mistyped) == Error(ticket.BadChecksum)
    })
  })
}

/// Up to eight substitutions at distinct positions are always caught: the
/// long codex32 code's guarantee (BIP-93), well inside its 1023-symbol
/// bound.
pub fn the_checksum_catches_up_to_eight_substitutions_test() {
  let substitution =
    qcheck.tuple2(qcheck.bounded_int(3, 129), qcheck.bounded_int(1, 31))

  property(
    qcheck.tuple2(
      tickets(),
      qcheck.generic_list(substitution, qcheck.bounded_int(1, 8)),
    ),
    fn(case_) {
      let #(made, edits) = case_
      let original = text(made)
      let last = string.length(original) - 1

      // Positions past a loopback ticket's end fold back into it, and a
      // position named twice keeps its first edit, so every edit changes a
      // distinct character.
      let edits =
        edits
        |> list.map(fn(edit) { #(3 + { edit.0 - 3 } % { last - 2 }, edit.1) })
        |> first_edit_per_position

      let mistyped =
        list.fold(edits, string.to_graphemes(original), fn(characters, edit) {
          let #(position, delta) = edit
          let assert Ok(current) = list_at(characters, position)
          let assert Ok([value]) = codex32.to_symbols(current)
          let changed = codex32.from_symbols([{ value + delta } % 32])
          string.to_graphemes(replace_at(characters, position, changed))
        })
        |> string.concat

      assert ticket.decode(mistyped) == Error(ticket.BadChecksum)
    },
  )
}

/// Whatever the decoder accepts re-encodes to exactly the text it read: no
/// checksummed string of any length is a second spelling of a ticket.
pub fn only_the_canonical_spelling_decodes_test() {
  let data =
    qcheck.generic_list(qcheck.bounded_int(0, 31), qcheck.bounded_int(0, 120))

  property(data, fn(data) {
    let candidate = checksummed(data)

    case ticket.decode(candidate) {
      Ok(made) -> {
        assert text(made) == candidate
      }

      Error(_) -> Nil
    }
  })

  // The generator above reaches valid tickets only by chance, so the
  // canonical encodings are checked through the same path too.
  list.each([onion_ticket(), loopback_ticket()], fn(made) {
    let assert Ok(back) = ticket.decode(checksummed(data_of(made)))
    assert back == made
  })
}

/// Strictness past the checksum: non-zero padding, an extra symbol, a
/// missing one, an unknown format, port zero and an onion label that is
/// not v3 are all refused even with a valid checksum.
pub fn a_valid_checksum_does_not_excuse_a_bad_payload_test() {
  let data = data_of(loopback_ticket())
  let assert [format, ..payload] = data
  let last = list.length(payload) - 1

  // The last symbol carries three padding bits; setting the lowest is a
  // second spelling of the same bytes.
  let padded =
    list.index_map(payload, fn(symbol, index) {
      case index == last {
        True -> symbol + 1
        False -> symbol
      }
    })
  assert ticket.decode(checksummed([format, ..padded]))
    == Error(ticket.BadPayload)

  assert ticket.decode(checksummed(list.append(data, [0])))
    == Error(ticket.BadPayload)
  assert ticket.decode(checksummed(list.take(data, list.length(data) - 1)))
    == Error(ticket.BadPayload)
  assert ticket.decode(checksummed([2, ..payload]))
    == Error(ticket.UnknownFormat)
  assert ticket.decode(checksummed([])) == Error(ticket.BadPayload)

  // Port zero: the loopback payload with its first two bytes cleared.
  let assert Ok(bytes) = codex32.symbols_to_bytes(payload)
  let assert <<_:size(16), key:bits>> = bytes
  assert ticket.decode(
      checksummed([format, ..codex32.bytes_to_symbols(<<0:16, key:bits>>)]),
    )
    == Error(ticket.BadPayload)

  // An onion label whose version byte is not 3.
  let onion = <<7:256, 1, 2, 4, 80:16, 9:256>>
  assert ticket.decode(checksummed([0, ..codex32.bytes_to_symbols(onion)]))
    == Error(ticket.BadPayload)
}

/// Uppercase, whitespace, another prefix, characters outside the alphabet
/// and text over the bound are not tickets.
pub fn only_the_exact_text_form_is_read_test() {
  let good = text(loopback_ticket())

  assert ticket.decode(string.uppercase(good)) == Error(ticket.NotATicket)
  assert ticket.decode(good <> "\n") == Error(ticket.NotATicket)
  assert ticket.decode(" " <> good) == Error(ticket.NotATicket)
  assert ticket.decode("ms1" <> string.drop_start(good, 3))
    == Error(ticket.NotATicket)
  assert ticket.decode("rw1b") == Error(ticket.NotATicket)
  assert ticket.decode("") == Error(ticket.NotATicket)
  assert ticket.decode(good <> string.repeat("q", 200))
    == Error(ticket.NotATicket)
}

/// Neither a ticket nor its keys print their secret.
pub fn a_ticket_does_not_print_its_secret_test() {
  let made = onion_ticket()
  let assert Ok(keys) = ticket.keys(fake_suite.suite(), made)
  let shown = string.inspect(made) <> string.inspect(keys)

  assert !string.contains(shown, text(made))
  assert !string.contains(shown, "rw1")
}

// ------------------------------------------------------------- derivation

/// The values derived from one secret are pairwise distinct even in their
/// first twelve bytes, so no two share a label (HKDF-Expand under one label
/// gives one output stream, whose prefixes would match); and two tickets
/// share none of them.
pub fn every_derived_value_is_distinct_test() {
  let suite = fake_suite.suite()

  property(qcheck.tuple2(tickets(), tickets()), fn(pair) {
    let #(first, second) = pair
    let assert Ok(one) = ticket.keys(suite, first)
    let assert Ok(two) = ticket.keys(suite, second)

    let prefixes = list.append(prefixes(one), prefixes(two))
    assert list.unique(prefixes) == prefixes
  })
}

/// The first twelve bytes of every derived value.
fn prefixes(keys: ticket.Keys) -> List(BitArray) {
  [
    id.to_bytes(keys.locator),
    capability.expose(keys.retrieve),
    secret.expose(keys.key),
    keys.nonce,
    secret.expose(keys.commit_key),
  ]
  |> list.map(fn(bytes) {
    let assert <<prefix:bytes-size(12), _:bits>> = bytes
    prefix
  })
}

/// Derivation is a function of the secret alone: the mailbox does not
/// enter it, and the same ticket always names the same blob.
pub fn derivation_depends_only_on_the_secret_test() {
  let suite = fake_suite.suite()
  let assert Ok(here) = ticket.from_parts(Loopback(port(1)), <<5:256>>)
  let assert Ok(one) = ticket.keys(suite, here)
  let assert Ok(two) = ticket.keys(suite, loopback_ticket())

  assert one == two
  assert bit_array.byte_size(two.nonce) == 12
}

// ------------------------------------------------------------------- blob

fn invitation(seed: Int) -> BitArray {
  <<"invitation file ":utf8, seed:size(64)>>
}

/// A sealed invitation opens under its own ticket, sealing is
/// deterministic, and the blob adds exactly its documented overhead.
pub fn a_sealed_invitation_opens_under_its_ticket_test() {
  let suite = fake_suite.suite()
  let assert Ok(keys) = ticket.keys(suite, onion_ticket())
  let assert Ok(blob) = ticket.seal(suite, keys, invitation(1))

  assert ticket.open(suite, keys, blob) == Ok(invitation(1))
  assert ticket.seal(suite, keys, invitation(1)) == Ok(blob)
  assert bit_array.byte_size(blob)
    == bit_array.byte_size(invitation(1)) + ticket.blob_overhead_bytes
}

/// A blob sealed for another ticket is refused by the AEAD: a mailbox that
/// answers with someone else's invitation is caught.
pub fn another_tickets_blob_is_refused_test() {
  let suite = fake_suite.suite()
  let assert Ok(mine) = ticket.keys(suite, onion_ticket())
  let assert Ok(theirs) = ticket.keys(suite, loopback_ticket())
  let assert Ok(blob) = ticket.seal(suite, theirs, invitation(2))

  assert ticket.open(suite, mine, blob) == Error(ticket.NotSealedForTicket)
}

/// The commitment is checked: a blob whose ciphertext opens under the key
/// but whose commitment names a different invitation is refused. Only
/// someone holding the ticket's secret can build one, which is the party
/// the commitment exists to bind.
pub fn a_substituted_invitation_is_refused_by_the_commitment_test() {
  let suite = fake_suite.suite()
  let assert Ok(keys) = ticket.keys(suite, onion_ticket())
  let assert Ok(<<version, _:bytes-size(32), sealed:bits>>) =
    ticket.seal(suite, keys, invitation(3))
  let other = suite.hmac_sha256(secret.expose(keys.commit_key), invitation(4))
  let forged = <<version, other:bits, sealed:bits>>

  assert ticket.open(suite, keys, forged) == Error(ticket.CommitmentMismatch)
}

/// Truncated blobs and blobs of another version never reach the AEAD.
pub fn a_malformed_blob_is_refused_test() {
  let suite = fake_suite.suite()
  let assert Ok(keys) = ticket.keys(suite, onion_ticket())
  let assert Ok(<<_, rest:bits>>) = ticket.seal(suite, keys, invitation(5))

  assert ticket.open(suite, keys, <<>>) == Error(ticket.MalformedBlob)
  assert ticket.open(suite, keys, <<1, 0:248>>) == Error(ticket.MalformedBlob)
  assert ticket.open(suite, keys, <<2, rest:bits>>)
    == Error(ticket.MalformedBlob)
}

// ---------------------------------------------------------------- helpers

/// Runs `check` only for positions after the `rw1` prefix.
fn skip_prefix(position: Int, check: fn() -> Nil) -> Nil {
  case position < 3 {
    True -> Nil
    False -> check()
  }
}

fn replace_at(characters: List(String), position: Int, with: String) -> String {
  characters
  |> list.index_map(fn(character, index) {
    case index == position {
      True -> with
      False -> character
    }
  })
  |> string.concat
}

/// Keeps the first edit for each position, in order.
fn first_edit_per_position(edits: List(#(Int, Int))) -> List(#(Int, Int)) {
  list.fold(edits, [], fn(kept, edit) {
    case list.key_find(kept, edit.0) {
      Ok(_) -> kept
      Error(Nil) -> list.append(kept, [edit])
    }
  })
}

fn list_at(values: List(a), position: Int) -> Result(a, Nil) {
  list.drop(values, position) |> list.first
}
