"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        # request_id -> {"t0": monotonic start, "ts": ISO start, "user_id", "input"}
        self._open: dict[str, dict] = {}
        # user_id -> request_id gần nhất, dùng khi caller không truyền request_id
        self._last_request: dict[str, str] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Lưu user + nội dung hỏi + thời điểm bắt đầu. Trả về request_id."""
        request_id = request_id or uuid.uuid4().hex[:12]
        self._open[request_id] = {
            "t0": time.perf_counter(),
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "input": text,
        }
        self._last_request[user_id] = request_id
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Lưu câu trả lời + quyết định của lớp bảo vệ + latency, append vào self.logs."""
        request_id = request_id or self._last_request.get(user_id)
        started = self._open.pop(request_id, None) if request_id else None
        latency_ms = (
            round((time.perf_counter() - started["t0"]) * 1000, 1) if started else None
        )
        entry = {
            "request_id": request_id,
            "timestamp": started["timestamp"] if started else utc_now_iso(),
            "user_id": user_id,
            "input": started["input"] if started else None,
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None) -> str:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
