# ADR-014 — The project is named Pondline, on the wire as well as in the docs

**Status**: accepted · **Date**: 2026-11-02 · **Spec ref**: §4.2, §5.2, §6.1

## Decision

**The project, its programs and its packages are renamed from Reedwire to
Pondline.** The commands are `pondline` and `pondline-mailbox`, the sidecar is
`pondline-tor`, and environment variables start with `PONDLINE_`.

**The name changes on the wire too.** Every domain-separation label changes
from `Reedwire_*_v1` to `Pondline_*_v1`, the mailbox media type becomes
`application/vnd.pondline.mailbox+tlv`, and the ticket's human-readable prefix
changes from `rw` to `pl`, so tickets start `pl1`. CryptoProfileV1 keeps its
version number, because no deployment of the old labels exists to tell apart.

**Dated records keep the name they were written under.** `docs/review/` changes
only where a citation names a moved file. Each earlier ADR that used the old
name is swept and carries an addendum pointing here.

## Why

"Have your agent drop mine a pondline" says what the system is for, and
Reedwire suggests no such use. The old name was marked provisional from the
start. Pond is also the real ancestor of the design
(`docs/design-intent.md`), though Pondline isn't a successor to it and doesn't
copy its implementation.

The old name could have stayed in the labels, since a label only has to be
unique and stable, and leaving it would have kept every derived key unchanged.
But the labels would then carry a name found nowhere else in the project, and
this is the last point where changing them costs nothing: nothing has shipped,
so no stored state or issued ticket depends on them.

The two names have the same length, as do the two prefixes, so no line wraps
differently and every `file:line` citation stays correct.

## Consequences

Tickets, state directories and databases from an earlier build don't work with
this one. A `rw1` ticket is refused as `NotATicket`, and a session from before
the change derives different keys. Any local test state has to be recreated.

Labels are now frozen under the new name. Changing one after a release means a
new profile, as it always did.

`pondline.com` isn't available to us and no trademark search has been done. A
conflict found later would reopen the name, and would cost a new profile once
something has shipped.
