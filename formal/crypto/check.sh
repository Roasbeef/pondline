#!/usr/bin/env bash
# check.sh: run every model under formal/crypto through ProVerif and judge
# the results against the expectations in the table below.
#
# Usage: formal/crypto/check.sh [-j N] [-k] [name...]
#
#   -j N   run N provers at once (default 2; other work shares the CPU)
#   -k     keep the generated .pv files and prover logs in formal/crypto/out
#   name   run only the named rows of the table
#
# A row names a model: a source file (pairing.pv.in for the handshake,
# ticket.pv.in for the sealed invitation) and a set of cpp macros applied to
# it. Each macro is either an adversary scenario or a deliberate defect in
# the protocol (the source lists both). The expectation is one letter per
# query, in the order the queries appear in the source: T means ProVerif
# must prove the query, F means it must find an attack. A query the prover
# can neither prove nor refute ("cannot be proved") never matches, so an
# inconclusive run fails the gate. Rows whose expectation holds an F are the
# intentionally broken variants (and the scenarios in which a property is
# known not to hold, such as a leaked invitation); a model where no variant
# produces an attack is not trusted, so those F cells are as much a part of
# the gate as the T cells.
#
# Exit status is 0 only when every row matches. Needs proverif (2.05 was
# used) and cpp on PATH; docs/formal/crypto.md says how both were installed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
jobs=2
keep=0
timeout_s=${PROVERIF_TIMEOUT:-1800}

while getopts "j:k" opt; do
  case $opt in
    j) jobs=$OPTARG ;;
    k) keep=1 ;;
    *) echo "usage: $0 [-j N] [-k] [name...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

command -v proverif >/dev/null || { echo "proverif not on PATH" >&2; exit 2; }
command -v cpp >/dev/null || { echo "cpp not on PATH" >&2; exit 2; }

# source | name | macros | expected
#
# pairing.pv.in, Q1..Q9:
# Q1 SK secret (joiner view)        Q6 inviter authenticates honest joiner
# Q2 first message key secret       Q7 joiner authenticates inviter
# Q3 Hello plaintext secret         Q8 same SK implies same two identities
# Q4 SK secret (inviter view)       Q9 same SK implies same transcript
# Q5 inviter authenticates any joiner
#
# ticket.pv.in, T1..T3:
# T1 invitation secret from the mailbox
# T2 a joiner opens only what the inviter sealed for its ticket
# T3 one blob opens to one invitation under every ticket
table=$(cat <<'EOF'
pairing | base                 |                                             | TTTTTTTTT
pairing | break_dh             | BREAK_DH                                    | TTTTTTTTT
pairing | quantum              | BREAK_DH BREAK_ED                           | TTTTTTTTT
pairing | pq_broken            | BREAK_KEM BREAK_ML                          | TTTTTTTTT
pairing | weak_kem             | WEAK_KEM                                    | TTTTTTTTT
pairing | leak                 | LEAK_INVITATION                             | TTTTFTTTT
pairing | leak_quantum         | LEAK_INVITATION BREAK_DH BREAK_ED           | TTTTFTTTT
pairing | leak_pq_broken       | LEAK_INVITATION BREAK_KEM BREAK_ML          | TTTTFTTTT
pairing | leak_weak_kem        | LEAK_INVITATION WEAK_KEM                    | TTTTFTTTT
pairing | fs_longterm          | REVEAL_LT                                   | TTTTTTTTT
pairing | fs_prekeys           | REVEAL_PREKEYS                              | FFTFTTTTT
pairing | fs_prekeys_leak      | REVEAL_PREKEYS LEAK_INVITATION              | FFFFFTTTT
pairing | lt_before            | REVEAL_LT_BEFORE                            | TTTTTTTTT
pairing | lt_before_leak       | REVEAL_LT_BEFORE LEAK_INVITATION            | TTTFFFTTT
pairing | no_sig_leak          | NO_TRANSCRIPT_SIG LEAK_INVITATION           | TTTTFTTTT
pairing | no_sig_leak_dh       | NO_TRANSCRIPT_SIG LEAK_INVITATION BREAK_DH  | TTTFFFTTT
pairing | no_ct_weak_kem       | NO_CT_IN_SIG WEAK_KEM                       | TTTTFFTTF
pairing | no_ct_weak_kem_kdf   | NO_CT_IN_SIG WEAK_KEM CT_IN_KDF             | TTTTTTTTT
pairing | ed_only_leak_ed      | ONE_HALF_ED LEAK_INVITATION BREAK_ED        | TTTTFTTTT
pairing | ed_only_leak_quantum | ONE_HALF_ED LEAK_INVITATION BREAK_ED BREAK_DH | TTTFFFTTT
pairing | ml_only_leak_pq      | ONE_HALF_ML LEAK_INVITATION BREAK_ML BREAK_KEM | TTTTFTTTT
pairing | ml_only_leak_ml_dh   | ONE_HALF_ML LEAK_INVITATION BREAK_ML BREAK_DH | TTTFFFTTT
pairing | no_ad                | NO_AD                                       | TTTTTTTTT
pairing | no_ad_leak           | NO_AD LEAK_INVITATION                       | TTTTFTFFF
ticket  | ticket_base                 |                                              | TTT
ticket  | ticket_noncommitting        | NONCOMMITTING_AEAD                           | TTT
ticket  | ticket_no_commitment        | NO_COMMITMENT                                | TTT
ticket  | ticket_leak                 | LEAK_TICKET                                  | FFT
ticket  | ticket_leak_noncommitting   | LEAK_TICKET NONCOMMITTING_AEAD               | FFT
ticket  | ticket_leak_nc_no_commit    | LEAK_TICKET NONCOMMITTING_AEAD NO_COMMITMENT | FFF
EOF
)

out=$(mktemp -d "${TMPDIR:-/tmp}/reedwire-formal-crypto.XXXXXX")
if [ "$keep" = 1 ]; then
  out="$here/out"
  rm -rf "$out"
  mkdir -p "$out"
fi

run_one() {
  local source=$1 name=$2 macros=$3 expected=$4
  local defs=()
  for m in $macros; do defs+=("-D$m"); done
  cpp -P -w "${defs[@]}" "$here/$source.pv.in" > "$out/$name.pv"
  local status=0 started=$SECONDS
  timeout "$timeout_s" proverif "$out/$name.pv" > "$out/$name.log" 2>&1 || status=$?
  local elapsed=$((SECONDS - started))
  # One letter per RESULT line, in query order. ProVerif adds a parenthesised
  # "RESULT (but ...)" line after a failed injective query; it is not a query
  # result and is skipped. A log with no RESULT line makes grep exit non-zero;
  # the "|| true" keeps that from ending this function before it names the row.
  local got
  got=$(grep '^RESULT ' "$out/$name.log" | grep -v '^RESULT (' | sed -e 's/.* is true\.$/T/' -e 's/.* is false\.$/F/' -e 's/.* cannot be proved\.$/?/' | tr -d '\n' || true)
  if [ "$status" = 124 ]; then got="${got}(timeout)"; fi
  if [ "$got" = "$expected" ]; then
    echo "ok    $name  $got  ${elapsed}s"
    return 0
  fi
  echo "FAIL  $name  expected $expected got $got  ${elapsed}s  (log: $out/$name.log)"
  return 1
}

names=("$@")
selected=()
while IFS='|' read -r source name macros expected; do
  source=$(echo "$source" | xargs)
  name=$(echo "$name" | xargs)
  macros=$(echo "$macros" | xargs)
  expected=$(echo "$expected" | xargs)
  [ -z "$name" ] && continue
  if [ ${#names[@]} -gt 0 ]; then
    keep_row=0
    for n in "${names[@]}"; do [ "$n" = "$name" ] && keep_row=1; done
    [ "$keep_row" = 1 ] || continue
  fi
  selected+=("$source|$name|$macros|$expected")
done <<< "$table"

failures=0
running=0
pids=()
for row in "${selected[@]}"; do
  IFS='|' read -r source name macros expected <<< "$row"
  run_one "$source" "$name" "$macros" "$expected" &
  pids+=($!)
  running=$((running + 1))
  if [ "$running" -ge "$jobs" ]; then
    wait "${pids[0]}" || failures=$((failures + 1))
    pids=("${pids[@]:1}")
    running=$((running - 1))
  fi
done
for pid in "${pids[@]}"; do
  wait "$pid" || failures=$((failures + 1))
done

if [ "$keep" = 0 ]; then rm -rf "$out"; fi
if [ "$failures" = 0 ]; then
  echo "all ${#selected[@]} models match"
  exit 0
fi
echo "$failures of ${#selected[@]} models did not match" >&2
exit 1
