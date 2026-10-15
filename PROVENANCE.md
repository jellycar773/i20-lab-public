# Provenance and scope

Prepared on 15 October 2026 from a review of the private I20 lab repository.

The starting offline component was `tools/i20_taskctl.py`, Git blob
`5ced5e08df959a256db56fe47b91f55b0abff311`, observed at repository revision
`0ffdc92bc641c6c2dc6609ecf45e7f709e789cd1`. Its companion tests were Git blob
`a687c324068ad8ff04d019b2aed7a7a93c548137`.

`lab/taskctl.py` is an **adaptation**, not a byte-for-byte export or a claim about
what is installed on the live server. It retains the core explicit-contract,
context-hash, immutable-task and result-inspection ideas. Differences include:

1. Research-specific target summaries and claims are replaced by synthetic
   contexts. No unpublished manuscript or current research result is included.
2. Context reads use descriptor-relative no-follow operations, reject hardlinks
   and special files, and check size before reading and source size before
   compilation. Output directories must be new and use private permissions.
3. A result report may be internally consistent, but never becomes authenticated
   or independently verified merely through JSON fields and hashes.
4. Result summaries omit raw notes, errors and machine-specific metadata.
5. New regression tests and the reviewed-file snapshot exporter are included.

The private protocol documents informed the architecture description. The
controller, scheduler, quota governor, native CLI adapters, independent Lean
checker and installers are **not** distributed here and have not been represented
as audited implementations in this release.

No claim of mathematical completeness, novelty, peer review or formal
certification is made by this public showcase. Infrastructure tests certify none
of those properties. No third-party provider binaries or credentials are included.
