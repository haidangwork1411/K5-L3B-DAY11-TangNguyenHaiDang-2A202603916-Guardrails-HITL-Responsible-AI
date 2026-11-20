"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from guardrails.output_guardrails import content_filter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


def _sanitize_log_text(text: str | None, *, max_len: int = 500) -> str:
    """Redact PII/secrets/API keys before writing text to audit logs."""
    raw = text if isinstance(text, str) else ""
    redacted = content_filter(raw)["redacted"]
    return redacted[:max_len]


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._pending: dict[str, dict] = {}

    def _entry_key(self, user_id: str, request_id: str | None) -> str:
        return request_id if request_id is not None else (user_id or "anonymous")

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store sanitized input and start timestamp keyed by request_id/user_id."""
        uid = user_id or "anonymous"
        key = self._entry_key(uid, request_id)
        self._open[key] = time.monotonic()
        self._pending[key] = {
            "request_id": request_id,
            "user_id": uid,
            "timestamp_start": utc_now_iso(),
            "input": _sanitize_log_text(text),
        }
        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store sanitized output, layer decision, latency; append to self.logs."""
        uid = user_id or "anonymous"
        key = self._entry_key(uid, request_id)
        start_mono = self._open.pop(key, None)
        pending = self._pending.pop(key, {})

        latency_ms = (
            round((time.monotonic() - start_mono) * 1000.0, 2)
            if start_mono is not None
            else None
        )
        now_iso = utc_now_iso()
        if blocked:
            status = "blocked"
        elif layer in {"api_error", "error"}:
            status = "error"
        else:
            status = "allowed"

        entry = {
            "request_id": request_id if request_id is not None else pending.get("request_id"),
            "user_id": uid,
            "timestamp_start": pending.get("timestamp_start") or now_iso,
            "timestamp_end": now_iso,
            "input": pending.get("input", ""),
            "output": _sanitize_log_text(text),
            "blocked": bool(blocked),
            "layer": layer,
            "status": status,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        out_path = Path(filepath) if filepath else Path(default_audit_log_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(out_path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
