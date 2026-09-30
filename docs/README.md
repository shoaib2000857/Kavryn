# Aegis documentation index

Public project name: **Kavryn**. Start with the [SDK quick start](SDK_QUICKSTART.md)
for installation, public imports, run scripts, and checked downloads. Historical
Aegis names and evidence IDs are retained for compatibility.

Start here for model-free local use and the latest repair/receipt safeguards:
[Reliability and operations](RELIABILITY_AND_OPERATIONS.md).

New: [Storage audit and offline SWE-bench pilot](STORAGE_AND_SWE_PILOT.md) — cleanup candidates, two-disk storage lesson, scoped external repair results and exact evaluation limits.

This directory is the project source of truth during research and implementation. The runtime is an early prototype; consult progress and active tasks for evidence-backed status.

## Reading order

For the latest runnable local-model work and measured comparisons, see
[Local evaluation](LOCAL_EVALUATION.md).

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
21. [Active tasks](ACTIVE_TASKS.md) — current implementation queue, completed work, and next milestones.

CI is defined in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). It does not
receive model credentials; CI results do not substitute for external benchmark runs.

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
