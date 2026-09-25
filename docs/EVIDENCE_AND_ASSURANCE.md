# Evidence model and assurance gate

## Terminology

The project uses **evidence-carrying patch** and **assurance gate** as its default language.

A finite collection of tests does not mathematically prove that a program is secure. “Proof” may be used only for a narrowly defined machine-checkable property with explicit assumptions. For normal vulnerability repair, Aegis reports empirical assurance and residual uncertainty.

## Evidence principles

- content-address every artifact;
- preserve raw input separately from parsed/normalized records;
- identify collector, adapter, version, time, target, and case;
- never silently overwrite evidence;
- distinguish observed, parsed, inferred, and verified facts;
- attach confidence to the method, not persuasive narrative;
- preserve negative and conflicting results;
- make every assurance claim traceable to evidence IDs.

## Conceptual entities

```text
Case
 |- ScopePolicy
 |- Asset
 |- Event
 |- Artifact
 |- ToolRun
 |- Finding
 |- Hypothesis
 |- ActionRequest
 |- PolicyDecision
 |- Approval
 |- PatchCandidate
 |- VerificationRun
 |- AssuranceDecision
 `- AuditEvent
```

## Minimal common envelope

Every stored record should include:

```json
{
  "schema_version": "aegis.example/v1",
  "id": "typed-unique-id",
  "case_id": "AGE-0001",
  "created_at": "RFC3339 timestamp",
  "producer": {"type": "adapter", "name": "semgrep", "version": "pinned"},
  "subject_refs": ["asset://..."],
  "source_refs": ["artifact://sha256/..."],
  "integrity": {"algorithm": "sha256", "digest": "..."},
  "classification": "internal",
  "payload": {}
}
```

## Finding schema

A finding should capture:

- vulnerability or behavior type;
- CWE/CVE where legitimately known;
- severity and source-specific confidence;
- affected asset, artifact, file, line, function, package, and version;
- supporting and contradicting evidence;
- reproduction state and reproducer reference;
- scanner/tool provenance;
- deduplication/correlation links;
- status and owner.

The system must not manufacture a CVE identifier or convert a tool's severity into universal ground truth.

### Initial investigation correlation

The experimental correlator creates a `hypothesis` only for same-case suspicious
telemetry when an explicit owner-authored route-to-source mapping matches a
normalized static finding and scan-source digest equals deployed-source digest.
The record links case-scoped artifact references for the normalized scanner result,
raw telemetry, and deployment provenance. The summary states that causal relevance
is unconfirmed. A matching route and finding is a triage lead, not proof that the
finding caused the observed event. This is required by the fixed path-traversal
Docker case before containment; persistence and generalized artifact retrieval
remain unimplemented.

## Patch candidate schema

- base repository and immutable commit;
- unified diff and digest;
- files/functions changed;
- model/provider/configuration and prompt-template version;
- evidence context references;
- stated root cause and repair invariant;
- generated/public tests;
- predicted behavior changes;
- known uncertainty;
- diff size/risk measures.

## Verification record

Each check reports:

```text
check_id, verifier_identity, verifier_image_digest, candidate_digest,
input_artifact_digests, command_adapter_version, start/end time,
exit classification, structured result, bounded log references,
resource use, infrastructure health, and signature/attestation.
```

## Assurance decisions

| Decision | Meaning |
| --- | --- |
| `VERIFIED` | All mandatory checks for the defined assurance profile passed and evidence integrity is intact. |
| `REVIEW_REQUIRED` | No hard rejection occurred, but required evidence is missing, ambiguous, flaky, or outside automated policy. |
| `REJECTED` | A candidate failed a mandatory security, functional, scope, or risk check. |
| `CONTROL_FAILURE` | The trusted evaluation/control process was violated or could not establish integrity. |

## Example assurance profile

For a reproducible application vulnerability:

| Check | Rule |
| --- | --- |
| Source integrity | Base commit and candidate diff digest must match case record |
| Clean build | Must complete in verifier image |
| Existing tests | All mandatory tests pass |
| Vulnerability replay | Original exploit/reproducer no longer succeeds |
| Positive behavior | Legitimate equivalent behavior still succeeds |
| Hidden security tests | All pass |
| Hidden regression tests | All pass |
| Security re-scan | Original finding absent or explicitly adjudicated |
| Diff policy | No forbidden files, test deletion, policy edits, or excessive unrelated changes |
| Evidence integrity | All required records and hashes valid |

## Hard failures

The following are non-compensating:

- build/load failure;
- successful original exploit replay;
- mandatory regression or hidden security test failure;
- patch modifies hidden tests, verifier, policy, audit configuration, or ground truth;
- out-of-scope file or dependency change;
- unexplained removal/weakening of security tests;
- evidence digest/signature mismatch;
- verifier infrastructure not healthy enough to trust the result; and
- action executed without required approval.

## Assurance package

```text
AGE-0001/
|- case.json
|- scope.json
|- source/
|  `- provenance.json
|- evidence/
|  |- raw/
|  |- normalized/
|  `- hypotheses.json
|- actions/
|  |- requests.jsonl
|  `- policy-decisions.jsonl
|- patch/
|  |- candidate.json
|  `- fix.diff
|- verification/
|  |- manifest.json
|  |- build.json
|  |- public-tests.json
|  |- exploit-replay.json
|  |- hidden-tests.json
|  `- security-rescan.sarif
|- recovery/
|  |- rollout.json
|  `- recurrence-window.json
|- assurance.json
`- audit-manifest.json
```

Large raw outputs remain separate content-addressed artifacts; manifests contain references and bounded summaries.

## Evaluation leakage controls

- evaluator ground truth and hidden tests are mounted only into the verifier;
- the defender sees only permitted observations and public fixtures;
- result messages expose pass/fail categories without leaking hidden input content;
- verifier images and datasets are version-pinned;
- the evaluation controller, not the agent, starts/stops attack replays;
- attempts to enumerate verifier resources become safety events.
