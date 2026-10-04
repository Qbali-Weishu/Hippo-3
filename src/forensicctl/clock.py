from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable



def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass(frozen=True)
class ClockModel:
    source: str
    segment: str
    offset_seconds: int
    trusted_pulses: tuple[str, ...]
    confidence: str = "high"

    def as_dict(self) -> dict[str, object]:
        return {
            "clock_segment": self.segment,
            "offset_seconds": self.offset_seconds,
            "trusted_pulses": list(self.trusted_pulses),
        }


class ClockRegistry:
    def __init__(self, models: dict[tuple[str, str], ClockModel]):
        self._models = models

    @classmethod
    def from_rows(cls, rows: Iterable[dict[str, str]]) -> "ClockRegistry":
        grouped: dict[tuple[str, str], list[tuple[int, str, str, str, str]]] = {}
        for row in rows:
            observed = parse_time(row["observed_at"])
            utc = parse_time(row["utc_at"])
            offset = int((utc - observed).total_seconds())
            key = (str(row["source"]), str(row["clock_segment"]))
            if not str(row.get("pulse_id", "")).strip():
                raise ValueError("clock pulse has no identity")
            confidence = str(row.get("confidence", "")).lower()
            if confidence not in {"high", "medium"}:
                raise ValueError(f"unsupported clock pulse confidence for {key[0]}/{key[1]}")
            grouped.setdefault(key, []).append((offset, str(row["pulse_id"]), confidence, str(row["observed_at"]), str(row["utc_at"])))
        if not grouped:
            raise ValueError("clock synchronization data is empty")
        models: dict[tuple[str, str], ClockModel] = {}
        for (source, segment), pulses in grouped.items():
            offsets = {pulse[0] for pulse in pulses}
            if len(offsets) != 1:
                raise ValueError(f"inconsistent clock correction for {source}/{segment}")
            pulse_ids = [pulse[1] for pulse in pulses]
            if len(pulse_ids) != len(set(pulse_ids)):
                raise ValueError(f"duplicate clock pulse for {source}/{segment}")
            models[(source, segment)] = ClockModel(
                source=source,
                segment=segment,
                offset_seconds=next(iter(offsets)),
                trusted_pulses=tuple(pulse[1] for pulse in sorted(pulses, key=lambda item: item[1])),
                confidence="high" if all(pulse[2] == "high" for pulse in pulses) else "medium",
            )
        return cls(models)

    def model_for(self, source: str, segment: str) -> ClockModel:
        try:
            return self._models[(source, segment)]
        except KeyError as exc:
            raise ValueError(f"missing clock model for {source}/{segment}") from exc

    def normalize(self, source: str, segment: str, observed_at: datetime) -> datetime:
        model = self.model_for(source, segment)
        return normalize(observed_at, {"offset_seconds": model.offset_seconds})

    def public(self) -> dict[str, dict[str, object]]:
        by_source: dict[str, list[ClockModel]] = {}
        for (source, _), model in self._models.items():
            by_source.setdefault(source, []).append(model)
        result: dict[str, dict[str, object]] = {}
        for source, models in sorted(by_source.items()):
            for model in sorted(models, key=lambda item: item.segment):
                key = source if len(models) == 1 else f"{source}/{model.segment}"
                result[key] = model.as_dict()
        return result


def normalize(value: datetime, model: dict[str, object]) -> datetime:
    return (value + timedelta(seconds=int(model["offset_seconds"]))).astimezone(timezone.utc)
