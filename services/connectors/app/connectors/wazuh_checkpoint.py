"""Completed Wazuh query windows, staged until their sinks accept them.

An event-time watermark cannot identify a duplicate: an older event can be
indexed for the first time after a newer one. Wazuh therefore replays a
bounded overlap, deduplicates alert document identities through BaseConnector,
and records the upper bound of each fully consumed query separately.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

Stream = Literal["alerts", "vulnerabilities"]
_STREAMS: tuple[Stream, ...] = ("alerts", "vulnerabilities")


def _timestamp(value: Any) -> datetime:
    """Read only an absolute, timezone-aware checkpoint timestamp."""
    if not isinstance(value, str):
        raise ValueError("Wazuh checkpoint timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Wazuh checkpoint timestamp must be an ISO-8601 string") from None
    if parsed.tzinfo is None:
        raise ValueError("Wazuh checkpoint timestamp must include a timezone")
    return parsed.astimezone(UTC)


class WazuhCheckpoint:
    """Keep alert and inventory progress distinct without owning persistence.

    Alert progress is eligible once the entire search has been consumed. The
    scheduler's existing full-ingest-acceptance gate owns its durable write.
    Inventory progress additionally needs explicit confirmation after the
    vulnerability transaction succeeds. A failed inventory sync must never
    inherit a successful alert poll's position.
    """

    def __init__(self, overlap_seconds: int = 300) -> None:
        self._overlap = timedelta(seconds=max(0, int(overlap_seconds)))
        self._completed: dict[Stream, datetime] = {}
        self._staged: dict[Stream, datetime] = {}
        self._inventory_confirmed = False
        self._invalid = False

    def load(self, checkpoint: dict[str, Any] | None) -> None:
        """Seed a new poll; never keep progress staged by an earlier fetch."""
        self._completed = {}
        self._staged = {}
        self._inventory_confirmed = False
        self._invalid = False
        if not isinstance(checkpoint, dict) or "version" not in checkpoint:
            # Wazuh did not checkpoint before this format existed. An older
            # generic cursor cannot prove a completed query window.
            return
        completed = checkpoint.get("completed_through")
        if checkpoint.get("version") != 1 or not isinstance(completed, dict):
            self._invalid = True
            return
        try:
            self._completed = {stream: _timestamp(completed[stream]) for stream in _STREAMS if stream in completed}
        except (ValueError, OverflowError):
            # Raise when fetching, not while seeding: the scheduler treats
            # a seed exception as best-effort, whereas a fetch exception
            # reliably withholds progress and records an unhealthy poll.
            self._invalid = True
            self._completed = {}

    def query_range(self, stream: Stream, since_seconds: int, *, now: datetime | None = None) -> dict[str, str]:
        """Freeze the range, expanding its start to recover a saved backlog."""
        if self._invalid:
            raise ValueError("Wazuh checkpoint is invalid; restore or clear it before polling")
        end = now or datetime.now(UTC)
        if end.tzinfo is None:
            raise ValueError("Wazuh query boundary must include a timezone")
        end = end.astimezone(UTC)
        start = end - timedelta(seconds=max(0, int(since_seconds)))
        previous = self._completed.get(stream)
        if previous is not None:
            start = min(start, previous - self._overlap)
        return {"gte": start.isoformat(), "lte": end.isoformat()}

    def stage(self, stream: Stream, completed_through: str) -> None:
        """Record a completely consumed search, never an intermediate page."""
        self._staged[stream] = _timestamp(completed_through)
        if stream == "vulnerabilities":
            self._inventory_confirmed = False

    def confirm_vulnerability_sync(self) -> None:
        """The inventory sink committed, or the completed search was empty."""
        self._inventory_confirmed = "vulnerabilities" in self._staged

    def snapshot(self, seen: Iterable[str]) -> dict[str, Any] | None:
        """Return eligible progress for the scheduler's acceptance gate."""
        progress = {stream: value for stream, value in self._staged.items() if stream == "alerts" or self._inventory_confirmed}
        if not progress:
            return None
        completed = dict(self._completed)
        for stream, value in progress.items():
            previous = completed.get(stream)
            completed[stream] = max(previous, value) if previous is not None else value
        return {
            "version": 1,
            "completed_through": {stream: value.isoformat() for stream, value in completed.items()},
            "seen": list(seen),
        }
