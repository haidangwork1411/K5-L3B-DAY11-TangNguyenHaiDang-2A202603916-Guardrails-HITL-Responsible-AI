"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def record_event(
        self,
        *,
        blocked: bool = False,
        rate_limited: bool = False,
        judge_checked: bool = False,
        judge_failed: bool = False,
    ) -> None:
        """Update counters from a single real pipeline request."""
        self.total_requests += 1
        if blocked:
            self.blocked_requests += 1
        if rate_limited:
            self.rate_limit_hits += 1
        if judge_checked:
            self.judge_checks += 1
            if judge_failed:
                self.judge_fails += 1

    def check_metrics(self) -> list[Alert]:
        """Compute rates and emit Alert objects when thresholds are exceeded."""
        alerts: list[Alert] = []

        if self.total_requests > 0:
            block_rate = self.blocked_requests / self.total_requests
            if block_rate > self.block_rate_threshold:
                alerts.append(
                    Alert(
                        metric="block_rate",
                        value=round(block_rate, 4),
                        threshold=float(self.block_rate_threshold),
                        message=(
                            f"Block rate {block_rate:.1%} exceeded threshold "
                            f"{self.block_rate_threshold:.1%} "
                            f"({self.blocked_requests}/{self.total_requests})."
                        ),
                    )
                )

        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            alerts.append(
                Alert(
                    metric="rate_limit_hits",
                    value=float(self.rate_limit_hits),
                    threshold=float(self.rate_limit_hit_threshold),
                    message=(
                        f"Rate-limit hits ({self.rate_limit_hits}) exceeded threshold "
                        f"({self.rate_limit_hit_threshold})."
                    ),
                )
            )

        if self.judge_checks > 0:
            judge_fail_rate = self.judge_fails / self.judge_checks
            if judge_fail_rate > self.judge_fail_rate_threshold:
                alerts.append(
                    Alert(
                        metric="judge_fail_rate",
                        value=round(judge_fail_rate, 4),
                        threshold=float(self.judge_fail_rate_threshold),
                        message=(
                            f"Judge fail rate {judge_fail_rate:.1%} exceeded threshold "
                            f"{self.judge_fail_rate_threshold:.1%} "
                            f"({self.judge_fails}/{self.judge_checks})."
                        ),
                    )
                )

        self.alerts = alerts
        return list(self.alerts)

    def export_json(self, filepath: str | None = None):
        """Write metrics + alerts to JSON under repo-root ``outputs/`` by default."""
        self.check_metrics()
        out_path = Path(filepath) if filepath else Path(default_metrics_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.snapshot(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(out_path)

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
