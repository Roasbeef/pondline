import Pondline

/-
Prints the axioms every main theorem depends on. `check.sh` runs this file
and fails unless each line names only Lean's standard axioms (`propext`,
`Classical.choice`, `Quot.sound`); `sorryAx` or `Lean.ofReduceBool` would
mean a proof was skipped or trusted to the compiler.
-/

open Pondline

-- TLV and BigSize.
#print axioms decodeBigSize_encode
#print axioms decodeBigSize_canonical
#print axioms parseRecords_encode
#print axioms parseRecords_canonical
#print axioms parse_injective
#print axioms parse_bound
#print axioms parse_encode
#print axioms decode_fail_closed
#print axioms runStream_odd_ignored
#print axioms builder_accepted
#print axioms builder_overflow_rejected

-- Padding.
#print axioms largest_bucket
#print axioms paddedSize_isSome
#print axioms paddedSize_spec
#print axioms paddedSize_mono
#print axioms pad_spec
#print axioms pad_none_iff
#print axioms fromWire_spec

-- Retention offers.
#print axioms offers_length
#print axioms offers_window
#print axioms offers_decreasing
#print axioms offers_full
#print axioms offers_at_deadline_refused
#print axioms slack_accepted_first
#print axioms slack_tight
#print axioms reach_accepted
#print axioms six_days_accepted
#print axioms reach_tight
#print axioms slack_le_window
#print axioms copy_first_offer_is_expiry
#print axioms copy_short_if_slack_exceeds_window
#print axioms copy_first_offer_is_expiry_prod

-- Retransmit schedule.
#print axioms dueAt_spec
#print axioms dueAt_exhausted
#print axioms retransmit_after_window
#print axioms chain_length
#print axioms chain_le_deadline
#print axioms chain_zero_latency
#print axioms chain_hours
#print axioms span_lower_bound
#print axioms day_outage_five_copies
#print axioms span_inside_retention
