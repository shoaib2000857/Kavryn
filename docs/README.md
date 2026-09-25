# Aegis documentation index

This directory is the project source of truth during the research and architecture phase.

## Reading order

1. [Project charter](PROJECT_CHARTER.md)
2. [Product requirements](PRODUCT_REQUIREMENTS.md)
3. [Architecture](ARCHITECTURE.md)
4. [Control plane](CONTROL_PLANE.md)
5. [Threat model](THREAT_MODEL.md)
6. [Workflows](WORKFLOWS.md)
7. [Evidence and assurance](EVIDENCE_AND_ASSURANCE.md)
8. [Model strategy](MODEL_STRATEGY.md)
9. [Tools and sandboxes](TOOLS_AND_SANDBOXES.md)
10. [Benchmarks and datasets](BENCHMARKS_AND_DATASETS.md)
11. [Incident lessons](INCIDENT_LESSONS.md)
12. [Reference-material synthesis](REFERENCE_SYNTHESIS.md)
13. [Research agenda](RESEARCH_AGENDA.md)
14. [MVP and roadmap](MVP_AND_ROADMAP.md)
15. [Implementation handoff](IMPLEMENTATION_HANDOFF.md)
16. [Decision log](DECISIONS.md)
17. [Open questions](OPEN_QUESTIONS.md)
18. [Worklog](WORKLOG.md)
19. [Source registry](SOURCES.md)
20. [Progress report](PROGRESS_REPORT.md)

## Status vocabulary

| Status | Meaning |
| --- | --- |
| **Proposed** | An option under consideration. |
| **Accepted** | A design decision recorded in `DECISIONS.md`. |
| **Implemented** | Code exists and its normal-path tests pass. |
| **Verified** | Acceptance tests, safety tests, and evidence checks pass in a reproducible environment. |
| **Deferred** | Intentionally excluded from the current phase. |

Documents describe the intended system. Unless a section explicitly says otherwise, components are not yet implemented.

## Documentation maintenance rule

Each pull request must update the affected requirements, decisions, threat entries, and roadmap status. Research results belong in versioned experiment reports; aspirational metrics do not belong in status tables.
