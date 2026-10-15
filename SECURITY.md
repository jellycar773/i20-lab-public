# Security boundaries

## Release verdict

This package is intended for **source disclosure and an offline demonstration**.
It is not a security certification of the private repository, any historical
commit, the installed controller, the server, or the provider accounts.

The publication review excludes operational data by construction. Only the exact
files in `release.py` are eligible for export. The gate verifies the manifest,
rejects extra payload files, non-text content, changed files, oversized content,
symlinks, hardlinks and special files, and checks selected credential and personal
metadata patterns. The archive has normalized paths, permissions and timestamps.
Git metadata and Python caches are never exported.

The pattern scanner is intentionally modest: unknown credential formats, encoded
secrets, arbitrary private prose and secrets split across strings are not reliably
detectable. Its negative result alone is not publication approval. The reviewed
allowlist and manual source review are essential. The manifest is an integrity
record, not a cryptographic signature or a substitute for reviewing changes.

## Runtime boundary

Only the offline preflight/inspection component is included. There is no live
intake, network listener, provider invocation, deployment script, CI workflow,
GitHub writer, or proof-checking service in this package. Tests and examples do
not consume subscription allowances.

Run it as an ordinary user in an owner-controlled directory, not as administrator.
The context root and its ancestors, output parent and interpreter environment
must be trusted. Do not point it at a credential directory. Submitted context is
copied into task JSON; this tool is not a general-purpose sanitizer of arbitrary
future inputs. Generated tasks stay private by default and are not submitted.

Context reads use descriptor-relative operations with no-follow flags and reject
hardlinks, special files, oversized files, and concurrent modification detected
by file metadata. These checks do not protect against a hostile owner controlling
the entire execution environment.

The Lean source filter is conservative lint, not a language parser or a sandbox.
No formal verification is performed here. Matching a JSON report's task, goal
hash and claimed axiom list does not establish that a checker ran. The inspector
therefore never authenticates provenance or asserts kernel confirmation. It also
omits free-form notes, errors and operational paths from its output.

## Private/public separation

Keep the operational control repository private. Public contributions must not be
fed directly to a credential-bearing worker. A production design needs explicit
maintainer authorization of immutable inputs, separation of secrets and execution,
resource limits, independently trusted verification, and reviewed outbound
publication. Those production controls are outside this demonstrator's scope.

Do not migrate private history, archived logs, issues, pull-request discussions,
releases, workflow artifacts, deployment keys or saved provider sessions into a
public repository. If an actual credential has been disclosed, remove its access
by revoking or rotating it; deleting its current file is not sufficient.

Report suspected exposure privately to the repository owner. Do not paste
credential values, private traces or exploit output into a public issue.

## References

Official GitHub documentation consulted for the publication boundary:

- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
- https://docs.github.com/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility
- https://docs.github.com/en/actions/reference/security/secure-use

These references describe general platform behavior, not a finding that the
private lab currently uses GitHub Actions or has leaked a credential.
