//// The parameter type and the one decoder the generated `daemon/sql` uses,
//// copied from parrot 2.3.0's `parrot/dev` (Apache-2.0) and trimmed to what
//// this package's statements need (ADR-007, addendum).
////
//// Parrot is a code generator, and only its `make gen-sql` half needs its
//// own dependencies (an HTTP client to fetch sqlc, a TOML reader, and the
//// rest). Depending on parrot at run time would ship all of them and start
//// `gleam_httpc` and `inets` with the node, so parrot is a dev dependency
//// and `scripts/gen-sql.sh` rewrites the generated `import parrot/dev` to
//// this module, under the same `dev` alias.
////
//// Every table is `STRICT` over `INTEGER`, `TEXT` and `BLOB`, so sqlc types
//// every parameter as one of the first three variants, or a nullable one.
//// Parrot's own type also has float, boolean, timestamp, date, list and
//// dynamic variants; they are left out, so a statement that would need one
//// fails to compile instead of failing to bind at run time.

import gleam/dynamic/decode
import gleam/option.{type Option}

/// One bound parameter of a generated statement.
pub type Param {
  /// An `INTEGER` column.
  ParamInt(Int)

  /// A `TEXT` column.
  ParamString(String)

  /// A `BLOB` column.
  ParamBitArray(BitArray)

  /// A nullable column: `None` binds `NULL`.
  ParamNullable(Option(Param))
}

/// Decodes a boolean that SQLite returns as the integer 0 or 1, as from an
/// `EXISTS`. Any other integer is a decode failure, not a truth value.
///
/// ## Examples
///
/// ```gleam
/// decode.run(dynamic.int(1), sql_param.bool_decoder())
/// // -> Ok(True)
/// ```
pub fn bool_decoder() -> decode.Decoder(Bool) {
  let int_to_bool =
    decode.int
    |> decode.then(fn(value) {
      case value {
        0 -> decode.success(False)
        1 -> decode.success(True)
        _ -> decode.failure(False, "a boolean stored as 0 or 1")
      }
    })

  decode.one_of(decode.bool, or: [int_to_bool])
}
