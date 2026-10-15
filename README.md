# I20 Lab
## Public architecture and offline demonstrator

A research workflow for finite, explicit tasks: a principal defines an obligation;
model workers attempt or attack it; computations produce inspectable evidence;
and an independent proof checker, where applicable, checks the exact formal
statement. The important boundary is between producing a plausible answer and
establishing what the evidence actually supports.

**This is a deliberately limited public showcase, not a complete distribution of
the private lab or its installed controller.** It contains an adapted version of
the real offline task-preflight component, a synthetic example, regression tests,
and a fail-closed snapshot exporter. Private research manuscripts, live queues,
provider sessions, machine configuration, result logs, and Git history are absent.

## What the code demonstrates

- Explicit task contracts: statement, assumptions, success criterion, reason to
  abandon an approach, requested assurance level, and project selection.
- Context bound to exact bytes using SHA-256, immutable task identities, and
  reproducible task/result-path calculation.
- Separation of model review, computation, internally consistent reports, and
  independently authenticated proof evidence.
- Public-release checks that restrict exports to reviewed files rather than
  relying on a broad copy followed by best-effort redaction.

The engine names in task JSON are metadata. **Nothing here launches an agent,
calls a provider, uses a saved login, submits a task, installs software, or runs a
Lean checker.** Submitted Python is syntax-checked with `compile`, not executed.

## Run locally

Use Python 3.11 or newer on Linux or macOS. Secure file reads require POSIX file
operations; unsupported systems fail closed. No third-party package installation
or provider account is required. Run from this directory:

```sh
python3 -m unittest discover -s tests -v
python3 release.py check
python3 -m lab.taskctl build examples/task.json \
  --context-root examples/context --out-dir ../i20-demo-output
```

The output directory must not already exist. Its parent must be owner-controlled.
The generated files are private by default and say `submitted: false`. The context
is an elementary polynomial identity, not an unpublished research result.

To build another history-free ZIP after an unchanged, successful check:

```sh
python3 release.py export --out ../i20-lab-public-reviewed.zip
```

The exporter refuses an existing destination. Any intentional source change
requires a fresh review and a new manifest; there is no automatic “approve all
changes” command. Checksums establish byte consistency, not author authenticity.

## Read next

[Architecture](docs/ARCHITECTURE.md) explains the private workflow and identifies
which components this demonstrator does and does not implement.
[Security](SECURITY.md) describes its boundaries and release procedure.
[Provenance](PROVENANCE.md) records the adaptation.

## Showing this work publicly

Share the checked ZIP, or put **only its extracted contents** into a new, empty
repository. Do not fork, mirror, or change the visibility of the private control
repository to publish this showcase. A clean subdirectory or branch does not
remove the original repository's other branches, old commits, or activity.

Before making the initial public commit, review its author name and email; use a
GitHub no-reply commit email when personal email disclosure is not intended.
Keep this public repository disconnected from the live worker. Do not attach the
private lab's credentials, webhooks, saved sessions, or self-hosted runners.
