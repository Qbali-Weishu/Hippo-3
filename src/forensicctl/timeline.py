from __future__ import annotations

from datetime import datetime, timedelta
import re

from .models import Event


def is_ordered(events: list[Event]) -> bool:
    return all(left.normalized_at <= right.normalized_at for left, right in zip(events, events[1:]))


def within_window(event: Event, start: datetime, end: datetime) -> bool:
    return start <= event.normalized_at < end


def related(parent: Event, child: Event, max_gap_seconds: int = 180) -> bool:
    if child.normalized_at < parent.normalized_at:
        return False
    return child.normalized_at - parent.normalized_at <= timedelta(seconds=max_gap_seconds)


def context_family(context: str) -> str:
    match = re.search(r"(\d+)$", context)
    return match.group(1) if match else context


def same_investigation(parent: Event, child: Event, max_gap_seconds: int = 1800) -> bool:
    return (
        context_family(parent.context) == context_family(child.context)
        and child.normalized_at >= parent.normalized_at
        and child.normalized_at - parent.normalized_at <= timedelta(seconds=max_gap_seconds)
    )
