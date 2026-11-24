"""Normalize chat-completion usage without losing prompt-cache partitions.

Both LangChain input_tokens and OpenAI-compatible prompt_tokens already include
cache reads/writes. LiteLLM's raw write fields survive in token_usage even when
the locked LangChain client does not recognize their names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _count(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdecimal():
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None
    return None


def _first_count(*values: Any) -> int | None:
    for value in values:
        count = _count(value)
        if count is not None:
            return count
    return None


@dataclass(frozen=True)
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_read_tokens: int | None = None
    cache_creation_tokens: int | None = None
    cache_creation_5m_tokens: int | None = None
    cache_creation_1h_tokens: int | None = None
    #: False for missing/malformed totals or impossible cache partitions. Such
    #: usage can accompany a gateway price but cannot support a local estimate.
    supports_estimate: bool = False


def extract_token_usage(response: Any) -> TokenUsage:
    """Read normalized LangChain and retained OpenAI-compatible usage together.

    A missing detail stays None. In particular, a LangChain cache_read field
    does not imply that its unrecognized cache-write field was zero.
    """
    usage = _mapping(getattr(response, "usage_metadata", None))
    metadata = _mapping(getattr(response, "response_metadata", None))
    raw = _mapping(metadata.get("token_usage"))
    details = _mapping(raw.get("prompt_tokens_details"))
    normalized = _mapping(usage.get("input_token_details"))
    prompt = _first_count(raw.get("prompt_tokens"), usage.get("input_tokens"))
    completion = _first_count(raw.get("completion_tokens"), usage.get("output_tokens"))
    supports_estimate = prompt is not None and completion is not None
    if prompt is None and completion is None:
        # Preserve an available rollup for token counters, but do not price an
        # unknown input/output split as though all tokens were input.
        prompt = _first_count(raw.get("total_tokens"), usage.get("total_tokens"))

    read = _first_count(details.get("cached_tokens"), raw.get("cache_read_input_tokens"), normalized.get("cache_read"))
    creation = _first_count(
        details.get("cache_creation_tokens"),
        raw.get("cache_creation_input_tokens"),
        details.get("cache_write_tokens"),
        normalized.get("cache_creation"),
    )
    ttl = _mapping(details.get("cache_creation_token_details")) or _mapping(raw.get("cache_creation"))
    short = _first_count(ttl.get("ephemeral_5m_input_tokens"), normalized.get("cache_creation_5m"))
    long = _first_count(ttl.get("ephemeral_1h_input_tokens"), normalized.get("cache_creation_1h"))
    if creation is None and short is not None and long is not None:
        creation = short + long
    if creation is None and (short is not None or long is not None):
        supports_estimate = False

    # An explicit malformed count must not silently become a full-price input
    # estimate. Retain other valid observations for diagnosis.
    for mapping, names in (
        (details, ("cached_tokens", "cache_creation_tokens", "cache_write_tokens")),
        (raw, ("cache_read_input_tokens", "cache_creation_input_tokens")),
        (normalized, ("cache_read", "cache_creation")),
        (ttl, ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens")),
    ):
        if any(name in mapping and mapping[name] is not None and _count(mapping[name]) is None for name in names):
            supports_estimate = False

    if (read or 0) + (creation or 0) > (prompt or 0):
        supports_estimate = False
        read = creation = short = long = None
    if creation is not None and (short is not None or long is not None) and (short or 0) + (long or 0) != creation:
        supports_estimate = False
        short = long = None
    # Nonstandard service tiers have different rates. The small fallback table
    # is standard text-token pricing, not a replacement for gateway accounting.
    if metadata.get("service_tier") not in (None, "default", "standard", "auto"):
        supports_estimate = False
    if any(name in normalized for name in ("priority", "flex", "priority_cache_read", "flex_cache_read")):
        supports_estimate = False
    if any(
        (_count(value) or 0) > 0
        for value in (
            details.get("audio_tokens"),
            normalized.get("audio"),
            _mapping(raw.get("completion_tokens_details")).get("audio_tokens"),
            _mapping(usage.get("output_token_details")).get("audio"),
        )
    ):
        supports_estimate = False

    return TokenUsage(prompt or 0, completion or 0, read, creation, short, long, supports_estimate)
