# Security and authorized-use policy

Aegis Defender is a defensive research project. Development and evaluation must be limited to:

- repositories owned by the operator or explicitly authorized for testing;
- isolated local or cloud cyber ranges;
- intentionally vulnerable fixtures;
- public benchmarks under their stated licenses and usage conditions; and
- synthetic telemetry and attack replays generated for research.

The project must not provide an unrestricted autonomous interface for targeting public systems. Discovery, validation, exploit replay, containment, and repair actions must be bound to a case-specific scope policy and executed through typed adapters in isolated workers.

## Security invariants

1. An LLM cannot change its permissions, policy, identity, budget, or audit configuration.
2. Model output is untrusted data until parsed, validated, and authorized.
3. Repositories, logs, alerts, issues, dependency metadata, and tool output are adversarial inputs.
4. External networking is denied by default and is never inherited transitively from a support service.
5. Credentials are short-lived, case-scoped, and delivered only to the adapter that needs them.
6. The reasoning runtime cannot edit the verifier, hidden tests, ground truth, or audit log.
7. Production-impacting or irreversible actions require explicit human approval.
8. A safe stop, refusal, or escalation is a successful outcome when evidence is insufficient.

## Vulnerabilities in Aegis

Do not publish working exploit details for Aegis before maintainers have had a reasonable opportunity to investigate. Until a private reporting channel is declared, open a minimal GitHub issue that requests a private contact without including sensitive reproduction details.

The project owner still needs to choose and publish a formal disclosure channel. This is tracked in [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md).
