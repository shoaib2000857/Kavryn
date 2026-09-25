# Source registry

Last reviewed: 2026-09-02. Prefer primary sources and re-check version-sensitive facts before publication or experiments.

## Incident and agent control

- [OpenAI technical report: OpenAI–Hugging Face incident](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) — technical timeline, infrastructure paths, access, and mitigations.
- [OpenAI: The Hugging Face incident and the road ahead](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) — public postmortem and response framing.
- [METR/Redwood investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/) — trajectory behavior, collaboration, evaluation evasion, and interpretive nuance.
- [Hugging Face incident disclosure](https://github.com/huggingface/blog/blob/main/security-incident-july-2026.md?plain=1) — third-party impact and Hugging Face response.
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

- [AutoPatchBench / CyberSecEval](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch) — executable C/C++ vulnerability repair and operational requirements.
- [Vul4J](https://github.com/tuhh-softsec/vul4j) and [archived dataset](https://zenodo.org/records/6383527) — reproducible Java vulnerabilities and PoV tests.
- [CVEfixes](https://github.com/secureIT-project/CVEfixes) — large vulnerability/fixing-commit corpus.
- [PrimeVul](https://github.com/DLVulDet/PrimeVul) — function-level real-world C/C++ vulnerability-detection dataset.
- [VulnLoc](https://github.com/nus-apr/vulnloc-benchmark) — reproducible sanitizer-based localization benchmark.
- [San2Patch](https://github.com/acorn421/san2patch-benchmark) — sanitizer-log-to-patch benchmark.
- [SEC-bench](https://arxiv.org/abs/2506.11791) — real-world software-security tasks for agents.
- [PatchEval](https://github.com/bytedance/PatchEval) — executable vulnerability-patching benchmark; leaderboard results are version-sensitive.
- [CyberGym-E2E](https://arxiv.org/abs/2606.04460) — vulnerability discovery, PoC generation, and patching across 920 vulnerabilities and 139 projects in the paper.
- [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) — open-ended threat hunting over large Windows event-log datasets.
- [SecRespond](https://arxiv.org/abs/2607.26791) — post-compromise detection and remediation ranges.
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) — reproducible security-event datasets.
- [Splunk Attack Range](https://github.com/splunk/attack_range) — instrumented cyber-range automation.
- [MITRE CALDERA](https://github.com/mitre/caldera) — ATT&CK-based adversary emulation platform.

## Standards and defensive knowledge

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
