# Contributing to Kavryn

Created and maintained by Shoaib Sadiq Salehmohamed. See NOTICE and CITATION.cff
for attribution and optional research citation.

Use Python 3.12+ and `uv sync --locked --extra dev`. Before proposing changes,
read AGENTS.md, SECURITY.md, accepted architecture decisions, and current tasks.
Run unit tests, Ruff, mypy and schema checks; run owned Docker integrations when
changing worker, range, or verifier behavior. Keep inference out of default CI.

Discuss architectural or security-boundary changes in an issue first. Submit
small reviewable pull requests with requirements, tests, threat impact, and
limitations documented. Do not fabricate results or weaken controls to pass tests.
Never submit credentials, private telemetry, benchmark caches, or unauthorized
target testing. Follow SECURITY.md for private vulnerability reporting.

Contributions intentionally submitted for inclusion are under Apache-2.0,
subject to the license's contribution terms. Preserve applicable third-party
license and attribution notices. No contributor license agreement is required
by this guide. Open a discussion before proposing a separate agreement.
