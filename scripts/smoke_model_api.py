"""Exercise the configured OpenAI-compatible model with a typed Aegis task.

The script makes one request by default and never prints the API key. It
uses a synthetic range-only containment example; the model can only return
a structured proposal/refusal/escalation and cannot execute an action.

Required environment:

    LLM_URL       endpoint root, with or without a trailing /v1
    LLM_API_KEY   bearer token

Optional environment:

    LLM_MODEL     defaults to qwen38
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from urllib.parse import urlsplit

from aegis.domain.policy import RiskTier
from aegis.providers.hosted import (
    HostedOpenAICompatibleProvider,
    HostedProviderConfig,
)
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ReasoningTask,
    TaskRole,
    ToolDescriptor,
)


def _base_url(endpoint: str) -> str:
    normalized = endpoint.rstrip("/")
    if normalized.endswith("/v1"):
        return normalized
    return normalized + "/v1"


async def _run(model: str, *, timeout_seconds: int) -> dict[str, object]:
    endpoint = os.environ.get("LLM_URL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "")
    if not endpoint or not api_key:
        raise SystemExit("Set LLM_URL and LLM_API_KEY in the environment first.")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("Refusing to send the API key to a non-local HTTP endpoint.")

    provider = HostedOpenAICompatibleProvider(
        HostedProviderConfig(
            base_url=_base_url(endpoint),
            model=model,
            timeout_seconds=timeout_seconds,
            reasoning_effort="none",
        ),
        api_key=api_key,
    )
    task = ReasoningTask(
        role=TaskRole.CONTAINMENT_PLANNING,
        case_id="AGE-SMOKE-0001",
        instructions=(
            "For this synthetic local cyber range, propose a reversible containment action. "
            "Use only an adapter id exactly as listed in available_tools. Do not describe or "
            "execute commands. Keep the rationale concise."
        ),
    )
    context = EvidenceContext(
        case_id="AGE-SMOKE-0001",
        evidence_refs=("evidence://AGE-SMOKE-0001/proxy-event-1",),
        summary=(
            "Synthetic range only: the service received a path traversal request. "
            "A temporary proxy rule can block this request pattern while preserving "
            "normal downloads. No public target or real incident is involved."
        ),
    )
    tools = (
        ToolDescriptor(
            id="range.proxy",
            category="reversible-range-containment",
            risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
            description="Apply a temporary request filter to the authorized local range proxy.",
        ),
    )
    limits = InferenceLimits(
        max_output_tokens=512,
        max_tool_calls=1,
        timeout_seconds=timeout_seconds,
    )
    started = time.perf_counter()
    proposal = await provider.propose(task, context, tools, limits)
    elapsed = time.perf_counter() - started

    if proposal.action is not None and proposal.action.adapter not in {tool.id for tool in tools}:
        raise SystemExit("Model returned an adapter outside the supplied tool set.")
    return {
        "ok": True,
        "model": model,
        "proposal_kind": proposal.kind.value,
        "adapter": proposal.action.adapter if proposal.action else None,
        "action_type": proposal.action.action_type if proposal.action else None,
        "rationale": proposal.rationale,
        "elapsed_seconds": round(elapsed, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", "qwen38"))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    try:
        result = asyncio.run(_run(args.model, timeout_seconds=args.timeout))
    except Exception as exc:
        result = {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        }
        print(json.dumps(result, indent=2))
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
