# Source registry

Last reviewed: 2026-09-25. Prefer primary sources and re-check version-sensitive facts before publication or experiments.

## Incident and agent control

- [OpenAI technical report: OpenAI–Hugging Face incident](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) — technical timeline, infrastructure paths, access, and mitigations.
- [OpenAI: The Hugging Face incident and the road ahead](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) — public postmortem and response framing.
- [OpenAI: The Hugging Face incident and other third-party impact from misaligned models](https://openai.com/hugging-face-incident-and-misalignment/) — September follow-up describing its continuing review and broader categories of third-party activity; subject to further updates.
- [METR/Redwood investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/) — trajectory behavior, collaboration, evaluation evasion, and interpretive nuance.
- [Hugging Face incident disclosure](https://github.com/huggingface/blog/blob/main/security-incident-july-2026.md?plain=1) — third-party impact and Hugging Face response.
- [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline) — Hugging Face's detailed reconstruction of the July intrusion and the boundaries crossed; incident-specific attributions are presented as the organization's published account.
- [OpenAI: Path to Astra](https://openai.com/index/path-to-astra/) — current naming conflict and cyber-model context.
- [BashArena](https://arxiv.org/abs/2503.20936) — agent capability/control evaluation with sabotage tasks.
- [SHADE-Arena](https://arxiv.org/abs/2506.15740) — monitoring long-horizon sabotage.
- [NIST agent hijacking competition](https://www.nist.gov/news-events/news/2025/01/nist-launches-genai-agent-hijacking-competition) — prompt-injection/tool-use attack evaluation.

## Models and serving

- [Official Z.ai GLM-5 family repository](https://github.com/zai-org/GLM-5) — GLM-5.2/5.3 model sizes, context, effort settings, and serving links.
- [GLM-5.2 model card](https://huggingface.co/zai-org/GLM-5.2) — weights, license metadata, and model details.
- [Z.ai developer documentation](https://docs.z.ai/guides/llm/glm-5) — hosted API and SDK usage. Check the GLM-5.2/5.3 pages for current IDs.
- [vLLM GLM-5 recipe](https://github.com/vllm-project/recipes/blob/main/models/zai-org/GLM-5.yaml) — example self-hosting topology and hardware guidance; pin a released recipe when implementing.
- [SGLang](https://github.com/sgl-project/sglang) and [vLLM](https://github.com/vllm-project/vllm) — candidate self-hosted serving engines.

## Repair, vulnerability, and SOC benchmarks

- [Vul4Py paper](https://arxiv.org/abs/2608.00692) — Python vulnerability-repair benchmark; paper describes 100 cases with paired exploit and project-functional oracles. A candidate [repository](https://github.com/tabudz/vul4py) at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898` describes the same dataset, but is not linked from the paper/publication page and declares no license; its harness executes metadata commands through `shell=True`. Treat provenance, terms, and isolation as unresolved; no benchmark code was executed.
- [Vul4Py author publication listing](https://happygirlzt.com/publications.html) — lists the paper with a `[Code]` label but no linked repository, so it does not establish that the candidate GitHub repository is the authors' intended artifact.
- [VulnGym](https://github.com/Tencent/VulnGym) — project-level vulnerability-hunting dataset/evaluator; v0.1.4 documents 408 entries, 393 human-audited entries, CC-BY-4.0 data, and recall-only metrics that do not penalize over-reporting. A metadata-only check of commit `cd69f7e163e08485ab5496115ae03439cda6e27e` found an evaluator/schema mismatch on 44 entries with documented line ranges; see `artifacts/benchmark_runs/vulngym-v014-evaluator-oracle-compat-20260925.json` for the diagnostic, not an Aegis score.
- [SWE-bench official Docker setup guide](https://github.com/SWE-bench/SWE-bench/blob/main/docs/guides/docker_setup.md) — current harness setup and disk/RAM guidance (the linked guide recommends at least 120 GB free).
- [AutoPatchBench / CyberSecEval](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch) — executable C/C++ vulnerability repair and operational requirements.
- [Vul4J](https://github.com/tuhh-softsec/vul4j) and [archived dataset](https://zenodo.org/records/6383527) — reproducible Java vulnerabilities and PoV tests; upstream currently documents 129 entries, dataset CC-BY-4.0, tooling GPL-3.0, and Java 7/8/11/16 requirements.
- [CVEfixes](https://github.com/secureIT-project/CVEfixes) — large vulnerability/fixing-commit corpus.
- [PrimeVul](https://github.com/DLVulDet/PrimeVul) — function-level real-world C/C++ vulnerability-detection dataset.
- [VulnLoc](https://github.com/nus-apr/vulnloc-benchmark) — reproducible sanitizer-based localization benchmark.
- [San2Patch](https://github.com/acorn421/san2patch-benchmark) — sanitizer-log-to-patch benchmark.
- [SEC-bench](https://arxiv.org/abs/2506.11791) — real-world software-security tasks for agents.
- [PatchEval](https://github.com/bytedance/PatchEval) — executable vulnerability-patching benchmark; leaderboard results are version-sensitive.
- [CyberGym-E2E](https://arxiv.org/abs/2606.04460) — vulnerability discovery, PoC generation, and patching across 920 vulnerabilities and 139 projects in the paper.
- [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) — open-ended threat hunting over large Windows event-log datasets; its paper reports 106 procedures and measured model results, not an Aegis evaluation.
- [SecRespond](https://arxiv.org/abs/2607.26791) — post-compromise detection and remediation ranges.
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) — reproducible security-event datasets.
- [Splunk Attack Range](https://github.com/splunk/attack_range) — instrumented cyber-range automation.
- [MITRE CALDERA](https://github.com/mitre/caldera) — ATT&CK-based adversary emulation platform.

## Standards and defensive knowledge

- [Docker `network create` reference](https://docs.docker.com/reference/cli/docker/network/create/) — documents `--internal` as restricting external access and the host/container connectivity caveat.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) — Govern, Identify, Protect, Detect, Respond, Recover.
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — incident-response recommendations aligned with CSF 2.0.
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) — secure software development practices.
- [MITRE ATT&CK](https://attack.mitre.org/) — adversary behavior knowledge base.
- [MITRE D3FEND](https://d3fend.mitre.org/) — defensive technique knowledge graph.
- [OCSF](https://schema.ocsf.io/) — open cybersecurity event schema.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — static-analysis result interchange.
- [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) — SBOM standards.
- [CSAF](https://oasis-open.github.io/csaf-documentation/) and [VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex) — vulnerability/advisory and exploitability exchange.

## Source-use notes

- Counts and leaderboard scores can change; record the exact dataset release/commit used.
- Vendor benchmark claims require independent reproduction before being used as Aegis evidence.
- News coverage may help discover developments but should not replace the linked primary reports.
- Research artifacts can contain dual-use code; run only in the authorized isolation model described by this repository.
