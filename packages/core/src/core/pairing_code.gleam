//// The spoken pairing code: a nameplate and three words (ADR-016).
////
//// A code such as `482719-cradle-noble-velvet` is how two operators pair by
//// voice. The six digits are the rendezvous nameplate, public and drawn by
//// the mailbox. The three words are from the BIP-39 English list
//// (`core/pairing_code/words`), eleven bits each, thirty-three bits in all,
//// and they are the password of the PAKE that follows, so they are a secret:
//// they are held, encoded and exposed as a `Secret`, and no error here
//// carries any part of the text.
////
//// ## Text form
////
//// ```text
//// code = nameplate "-" word "-" word "-" word
//// ```
////
//// The decoder is total and strict because the code is typed by a person and
//// the first wrong guess spends it. A mistyped word must be refused here,
//// locally, so that it never reaches the rendezvous and is never counted as
//// a failed confirmation. So `decode` accepts exactly the text `encode`
//// produces and nothing near it: at most `limits.max_pairing_code_bytes`,
//// lowercase ASCII letters, digits and hyphens only, exactly one hyphen
//// between parts, a nameplate of exactly `limits.nameplate_digits` digits,
//// exactly `limits.pairing_code_words` words and every word on the list.
//// There is no case folding and no trimming; a caller that reads a terminal
//// trims the line first, because a decoder that guessed at what the person
//// meant would also guess at what an attacker meant.
////
//// ## Drawing words
////
//// `generate` takes the words from `Suite.random`: the first five bytes
//// are read as consecutive eleven-bit big-endian fields. The list has 2048
//// words, a power of two, so a field is an index as it stands and no
//// modulo bias skews the draw.
////
//// ## The password
////
//// `password` is the bytes `word1-word2-word3` in ASCII, the string the PAKE
//// takes as its password. The nameplate is public context, not password.

import core/crypto/suite.{type Suite}
import core/limits
import core/nameplate.{type Nameplate}
import core/pairing_code/words
import core/secret.{type Secret}
import gleam/bool
import gleam/list
import gleam/result
import gleam/string

/// A pairing code: the public nameplate and the secret words. Opaque, so a
/// value is always a code the decoder would accept, and the words sit in a
/// `Secret`, so a code prints as a closure.
pub opaque type PairingCode {
  PairingCode(nameplate: Nameplate, password: Secret)
}

/// Why text is not a pairing code. No variant carries any of the text, not
/// even a word, because a code is a secret and an error is logged.
pub type CodeError {
  /// Longer than `limits.max_pairing_code_bytes`.
  TooLong

  /// Not the shape of a code: a character outside lowercase ASCII letters,
  /// digits and hyphens, an empty part, or the wrong number of parts.
  BadShape

  /// The first part is not exactly `limits.nameplate_digits` digits.
  BadNameplate

  /// A word is not on the list. `position` counts from one, so a person is
  /// told which word to check and the word itself stays out of the error.
  UnknownWord(position: Int)
}

/// A fresh code for a nameplate, its words drawn from the suite's
/// randomness. A suite that returned fewer bytes than asked has broken the
/// contract of `random`; the missing fields read as zero rather than the
/// call failing, so only a conforming suite is a safe one.
///
/// ## Examples
///
/// ```gleam
/// pairing_code.generate(suite, nameplate)
/// // -> a code with three uniformly drawn words
/// ```
pub fn generate(suite: Suite, nameplate: Nameplate) -> PairingCode {
  let bits = suite.random(bytes_drawn())

  // Every index is below `words.word_count`, so every lookup succeeds and
  // `filter_map` drops nothing; the total form keeps a panic out of `src`.
  let spoken =
    bits
    |> read_indices(limits.pairing_code_words, [])
    |> list.filter_map(words.word_at)

  PairingCode(nameplate:, password: join_words(spoken))
}

/// The code's text, `NNNNNN-word-word-word`, as a `Secret` because the words
/// are the password.
///
/// ## Examples
///
/// ```gleam
/// secret.expose(pairing_code.encode(code))
/// // -> <<"482719-cradle-noble-velvet":utf8>>
/// ```
pub fn encode(code: PairingCode) -> Secret {
  // The password is exposed only to be spelled after the nameplate in the
  // code's own text, which is itself returned as a secret.
  let spoken = secret.expose(code.password)
  let plate = nameplate.to_string(code.nameplate)

  secret.new(<<plate:utf8, "-":utf8, spoken:bits>>)
}

/// Reads a code from text. Total over every string, and strict: whatever it
/// accepts, `encode` spells back as the same text.
///
/// ## Examples
///
/// ```gleam
/// pairing_code.decode("482719-cradle-noble-velvet")
/// // -> Ok(code)
/// ```
///
/// ```gleam
/// assert pairing_code.decode("482719-Cradle-noble-velvet")
///   == Error(pairing_code.BadShape)
/// ```
pub fn decode(text: String) -> Result(PairingCode, CodeError) {
  use <- bool.guard(
    string.byte_size(text) > limits.max_pairing_code_bytes,
    Error(TooLong),
  )
  use <- bool.guard(!is_code_alphabet(text), Error(BadShape))

  // The alphabet check admits no whitespace and no uppercase, so a split on
  // the hyphen yields the parts exactly as typed, empty ones included.
  let parts = string.split(text, "-")

  // A doubled, leading or trailing hyphen leaves an empty part. It is the
  // shape that is wrong, not a nameplate or a word, so it is named as such.
  use <- bool.guard(list.contains(parts, ""), Error(BadShape))
  use #(plate, spoken) <- result.try(split_nameplate(parts))

  // The number of parts is a property of the shape, so it is settled before
  // any part is read as a nameplate or a word.
  use <- bool.guard(
    !has_word_count(spoken, limits.pairing_code_words),
    Error(BadShape),
  )
  use nameplate <- result.try(
    nameplate.parse(plate) |> result.replace_error(BadNameplate),
  )
  use Nil <- result.try(check_words(spoken, 1))

  Ok(PairingCode(nameplate:, password: join_words(spoken)))
}

/// The code's public nameplate.
///
/// ## Examples
///
/// ```gleam
/// nameplate.to_string(pairing_code.nameplate(code))
/// // -> "482719"
/// ```
pub fn nameplate(code: PairingCode) -> Nameplate {
  code.nameplate
}

/// The PAKE password: the bytes of `word1-word2-word3` in ASCII, without the
/// nameplate.
///
/// ## Examples
///
/// ```gleam
/// secret.expose(pairing_code.password(code))
/// // -> <<"cradle-noble-velvet":utf8>>
/// ```
pub fn password(code: PairingCode) -> Secret {
  code.password
}

/// Separates the nameplate part from the word parts. `string.split` always
/// returns at least one part, so the empty arm is the type's, not a state.
fn split_nameplate(
  parts: List(String),
) -> Result(#(String, List(String)), CodeError) {
  case parts {
    [plate, ..spoken] -> Ok(#(plate, spoken))
    [] -> Error(BadShape)
  }
}

/// The bytes `generate` asks the suite for: enough for every word's bits.
fn bytes_drawn() -> Int {
  { limits.pairing_code_words * words.index_bits + 7 } / 8
}

/// Reads `remaining` consecutive eleven-bit big-endian fields.
fn read_indices(
  bits: BitArray,
  remaining: Int,
  collected: List(Int),
) -> List(Int) {
  use <- bool.lazy_guard(remaining <= 0, fn() { list.reverse(collected) })

  // Eleven whole bits are one index; anything less is a short draw.
  case bits {
    <<index:size(11), rest:bits>> ->
      read_indices(rest, remaining - 1, [index, ..collected])

    // A suite that returned too few bits has broken `random`'s contract;
    // the field reads as the first word instead of failing the call.
    _ -> read_indices(<<>>, remaining - 1, [0, ..collected])
  }
}

/// The words joined by hyphens, as the password's bytes.
fn join_words(spoken: List(String)) -> Secret {
  secret.new(<<string.join(spoken, "-"):utf8>>)
}

/// Whether every character is a lowercase ASCII letter, a digit or a hyphen.
fn is_code_alphabet(text: String) -> Bool {
  text
  |> string.to_utf_codepoints
  |> list.all(fn(point) { is_code_point(string.utf_codepoint_to_int(point)) })
}

/// Whether one code point is in the alphabet of a code.
fn is_code_point(point: Int) -> Bool {
  let digit = point >= 0x30 && point <= 0x39
  let lowercase = point >= 0x61 && point <= 0x7a
  digit || lowercase || point == 0x2d
}

/// Whether exactly `remaining` parts are left. Counted by walking at most
/// `remaining` parts, so a long input is not measured whole.
fn has_word_count(spoken: List(String), remaining: Int) -> Bool {
  case spoken {
    [] -> remaining == 0
    [_, ..rest] -> remaining > 0 && has_word_count(rest, remaining - 1)
  }
}

/// Checks that each part is on the list, naming the first word that is not.
/// `position` counts from one.
fn check_words(spoken: List(String), position: Int) -> Result(Nil, CodeError) {
  case spoken {
    [] -> Ok(Nil)

    // A word is checked at its position, and only the position is reported.
    [word, ..rest] -> {
      use _ <- result.try(
        words.index_of(word) |> result.replace_error(UnknownWord(position:)),
      )
      check_words(rest, position + 1)
    }
  }
}
