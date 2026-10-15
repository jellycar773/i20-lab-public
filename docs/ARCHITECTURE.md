# Architecture and trust boundaries

## Private research workflow

The private lab uses a repository as a control-and-evidence plane. A principal
submits finite, explicit tasks or batches. A worker controller accepts supported
inputs, schedules work, collects declared artifacts and publishes result records.
Task dependencies refer to explicit artifacts and hashes rather than relying on
a model's memory or an inaccessible local file path.

The logical flow is:

```text
Principal defines an exact obligation
             |
             v
Private task/batch intake ----> Controller admission and resource checks
                                             |
                                +------------+------------+
                                |                         |
                         Model attempt/review       Local computation
                                |                         |
                                +------------+------------+
                                             |
                                   Declared artifacts
                                             |
                              Independent checker, when applicable
                                             |
                                  Private evidence records
                                             |
                              Principal evaluates actual evidence
```

This is a description of the documented private workflow, not an assertion that
every component has been source-audited or is currently running. Live status
requires fresh observations; a historical heartbeat does not establish liveness.

## What this package implements

`lab/taskctl.py` implements **offline preparation**, not the controller. It checks
an explicit contract, inlines exact hash-checked context, creates task bytes and a
receipt, and checks the consistency of an optional result report. Its expected
result-path calculation is the offline component's task-blob convention; it does
not implement the complete batch controller's node/dependency identity scheme.

`release.py` implements a separate source-publication boundary. It exports only a
fixed, reviewed text-file allowlist after manifest and pattern checks. It does
not upload files or change repository visibility.

There is no model orchestration daemon, quota reader, provider login flow,
independent Lean runtime or production installation path in this public copy.
Those components require a separate full-source review before distribution.

## Evidence is not one Boolean flag

A task may pass preflight but never execute. A model may return a correct-looking
argument without a proof. A computation can refute a finite claim without proving
a universal one. A JSON record can be internally consistent yet forged. A genuine
kernel check can establish the submitted formal type without establishing that
it faithfully encodes the intended mathematical theorem.

Accordingly, the public inspector reports byte consistency separately from
provenance and independent verification. The latter two remain false: this
program has no trusted verifier or authenticated controller channel.

## Why the public repository is separate

A public code contribution is untrusted input. It must not become a job with
access to the owner's live provider sessions merely because it appears in an
issue, pull request, branch, or model-generated recommendation. Public code and
private operational authority are distinct concerns.

The showcase deliberately has no connection to the private intake and no outbound
result publication. Showing the architecture therefore does not expose a new
execution path into the live lab or inherit its operational history.
