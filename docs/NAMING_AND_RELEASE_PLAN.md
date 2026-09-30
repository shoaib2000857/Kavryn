# Naming and SDK release preparation

## Current status — Kavryn selected

Owner approved Kavryn and Apache-2.0, and authorized Git push/repository rename.
The `kavryn` distribution, SDK facade, CLI, typed markers, attribution files,
install/demo scripts and archive checks are implemented. Existing `aegis` imports
and evidence schemas remain compatible. Wheel/source archives have built locally;
see [SDK quick start](SDK_QUICKSTART.md). Registry publication and a tagged release
are not claimed. Earlier notes below describe the naming process, not current
license/package status. Attribution follows Apache terms plus optional citation.

Date: 2026-10-01. Owner authorized preparation of a downloadable toolkit/SDK
and asked to settle a lasting name first. No public upload, repository rename,
package reservation, license selection, or namespace migration has occurred.

**Update:** The owner prefers a shorter Aegis-like name, so PraxisSeal below is
not accepted. Current recommendation is **Kavryn** (six letters, pronounced
"KAV-rin"), pending owner confirmation. Exact software/SDK searches surfaced no
obvious same-category project; the PyPI `kavryn` metadata endpoint returned 404.
A GitHub handle appears in search results; this is not a uniqueness guarantee.
No trademark, domain, or registrability clearance is claimed.

**Latest decision:** Owner accepted **Kavryn** (ADR-067); PraxisSeal is rejected.
Rename/package/import migration is pending, not implemented by this document.
The owner clarified Linux was inspiration, not a license selection (ADR-066).
The accidentally added draft GPL license was removed and metadata restored to
`UNLICENSED`. Apache-2.0 is recommended, pending explicit approval; no license
is selected. The previous recommendation wording is historical research.

## Proposed identity — awaiting owner confirmation

**PraxisSeal** — transactional execution for AI agents.

Tagline: **Agents propose. Evidence decides.**

Proposed distribution/CLI/import name: `praxisseal`. Components can be described
as PraxisSeal Runtime, Defender, Bench, and Monitor, without publishing four
separate packages prematurely. The name conveys action plus evidence, not a
promise that every action is secure or mathematically proven.

### Preliminary collision checks

Exact-name web searches did not surface a PraxisSeal project. Direct public
registry metadata requests returned HTTP 404 for both
`https://pypi.org/pypi/praxisseal/json` and
`https://registry.npmjs.org/praxisseal` on this date. That means no package was
returned at those endpoints at check time, not guaranteed registrability,
reservation, domain availability, or trademark clearance. GitHub namespace and
relevant trademark/domain checks still need completion before public branding.

Several initial alternatives were discarded after discovering existing uses:

- ActBound: adjacent AI-agent governance, https://www.actbound.tech/.
- Actrail: existing Python SDK, https://pypi.org/project/actrail/1.0.2/.
- Kriyant: existing IT company, https://www.kriyant.com/.
- Kriyava: existing AI execution platform, https://kriyava.com/.

Veylant and VeriLatch also surfaced existing name uses. Stop broad naming
searches here; owner preference should drive the next step.

## Packaging assessment

The repository already has Hatchling packaging, Python >=3.12, a minimal
Pydantic dependency, optional development tools, and an installed CLI entry
point. Metadata currently uses `aegis-defender`, version `0.1.0`, and
`UNLICENSED`. There is no selected repository license. Public open-source
release must not silently replace that owner decision.

## Release work after the name is confirmed

- Record the name decision and namespace/version compatibility strategy.
- Create a deliberate public SDK facade over existing broker/coordinator APIs;
  preserve historical schema identifiers and evidence compatibility unless a
  versioned migration explicitly changes them.
- Update distribution metadata, CLI/help, current docs, and SDK examples;
  keep historical benchmark records truthful rather than rewriting their IDs.
- Build wheel and source archive with explicit inclusion rules. Exclude local
  environment files, credentials, downloaded benchmarks, databases, and run
  artifacts. Verify archive contents and install in a fresh environment.
- Exercise imports, doctor, model-free commit/rollback demo, and supported
  inspection commands from the installed wheel outside the source checkout.
- Add reviewed setup/run scripts without root privileges, model downloads,
  Docker socket grants, or curl-to-shell defaults.
- Add release checks/automation that build and test artifacts; do not upload
  them or create GitHub releases without an explicit publication step.
- Obtain owner-selected license, private security-reporting contact, and
  package/repository publication destinations before a public release.

No new permissions, secrets, tools, or effectful network operations were added
in this naming pass. Work consisted of read-only repository/registry/search
inspection and this planning document. Model testing remains deferred.
