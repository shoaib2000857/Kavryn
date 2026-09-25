from __future__ import annotations

from aegis.providers.base import ReasoningProvider
from aegis.providers.replay import ReplayProvider
from aegis.providers.stub import StubProvider


def test_stub_provider_satisfies_the_reasoning_provider_protocol() -> None:
    assert isinstance(StubProvider(), ReasoningProvider)


def test_replay_provider_satisfies_the_reasoning_provider_protocol() -> None:
    assert isinstance(ReplayProvider(()), ReasoningProvider)


def test_plain_object_does_not_satisfy_the_protocol() -> None:
    assert not isinstance(object(), ReasoningProvider)
