# Security policy

## Supported versions

Only the latest state of the `main` branch is supported. There are no
releases and no backports; this is a best-effort "utakata" project and
maintenance may stop at any time.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this
repository (Security tab → "Report a vulnerability"). Do not open a
public issue for a vulnerability, and do not include credentials, real
MAC addresses, or network details of any live deployment in a report.

Reports are read on a best-effort basis. There is no response-time
commitment, but reports that show a concrete path to harm — for
example a way for a non-root local user to obtain a ban or release
they should not be able to cause, or a way for detection data to be
treated as instructions by the verification loop — are taken
seriously.

## Scope notes

activeban is a control layer. It assumes the host it runs on, the
detector accounts, and the enforcement commands are trusted local
components; the authority model is described in `docs/design.md`.
Findings that require an already-privileged local account (root, the
daemon user, or the LLM account) to exploit are generally out of
scope, except where they cross one of the documented role boundaries.
