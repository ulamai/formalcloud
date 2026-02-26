from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .utils import utc_now_iso


class TraceLogger:
    def __init__(self, output_path: Path | None):
        self.output_path = output_path
        self._events: list[dict[str, Any]] = []
        self._seq = 0

    def event(self, name: str, payload: dict[str, Any] | None = None) -> None:
        self._seq += 1
        self._events.append(
            {
                "seq": self._seq,
                "timestamp": utc_now_iso(),
                "event": name,
                "payload": payload or {},
            }
        )

    def flush(self) -> None:
        if not self.output_path:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(json.dumps(event, sort_keys=True, ensure_ascii=True))
                handle.write("\n")
