#!/usr/bin/env python3
"""Emit a CiUsageReport/v1 describing 30 days of GitHub Actions consumption.

The report is telemetry, never a gate. It opens an issue only when growth is both
proportionally and absolutely material, so a small estate cannot trip an alert by
doubling a tiny number.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

API_VERSION = "github.mindclade.io/v1"
KIND = "CiUsageReport"
WINDOW_DAYS = 30
GIB = 1024**3

# Each threshold pairs a ratio with an absolute floor, and both must be exceeded.
# A ratio alone fires on noise in a small estate; an absolute alone never fires
# while the estate is small and fires constantly once it is large.
MINUTES_RATIO, MINUTES_ABSOLUTE = 0.20, 60.0
JOB_START_RATIO, JOB_START_ABSOLUTE = 0.15, 25.0
ARTIFACT_RATIO, ARTIFACT_ABSOLUTE = 0.25, float(GIB)
CACHE_UTILIZATION = 0.80

# Named so the except clauses stay single-name. Under target-version py314 ruff
# rewrites an inline tuple to PEP 758 unparenthesised form, which older
# interpreters cannot parse; a name is valid on every version.
TRANSIENT_REQUEST_ERRORS = (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError)
BASELINE_DECODE_ERRORS = (OSError, KeyError, TypeError, json.JSONDecodeError)


def measurement(current: float | None, baseline: float | None) -> dict[str, Any]:
    """Normalise a current/baseline pair, recording whether it was observed."""
    observed = current is not None and baseline is not None
    current_value = float(current or 0.0)
    baseline_value = float(baseline or 0.0)
    delta = current_value - baseline_value
    ratio = (delta / baseline_value) if baseline_value > 0 else 0.0
    return {
        "current": current_value,
        "baseline": baseline_value,
        "delta_absolute": delta,
        "delta_ratio": ratio,
        "observed": observed,
    }


def _grew(entry: dict[str, Any], ratio: float, absolute: float) -> bool:
    return (
        bool(entry["observed"])
        and entry["delta_ratio"] >= ratio
        and entry["delta_absolute"] >= absolute
    )


def evaluate_alerts(spec: dict[str, Any]) -> list[str]:
    """Return the alert identifiers a spec triggers, in a stable order."""
    alerts: list[str] = []
    if _grew(spec["minutes"], MINUTES_RATIO, MINUTES_ABSOLUTE):
        alerts.append("minutes_growth")
    if _grew(spec["job_starts"], JOB_START_RATIO, JOB_START_ABSOLUTE):
        alerts.append("job_start_growth")
    cache = spec["cache_bytes"]
    limit = float(spec["cache_limit_bytes"])
    if cache["observed"] and limit > 0 and cache["current"] / limit >= CACHE_UTILIZATION:
        alerts.append("cache_utilization")
    if _grew(spec["artifact_bytes"], ARTIFACT_RATIO, ARTIFACT_ABSOLUTE):
        alerts.append("artifact_growth")
    return alerts


def build_report(
    organization: str,
    source_revision: str,
    observed_at: str,
    minutes: dict[str, Any],
    job_starts: dict[str, Any],
    cache_bytes: dict[str, Any],
    cache_limit_bytes: float,
    artifact_bytes: dict[str, Any],
) -> dict[str, Any]:
    spec = {
        "minutes": minutes,
        "job_starts": job_starts,
        "cache_bytes": cache_bytes,
        "cache_limit_bytes": float(cache_limit_bytes),
        "artifact_bytes": artifact_bytes,
        "alerts": [],
        "alerting": False,
    }
    spec["alerts"] = evaluate_alerts(spec)
    spec["alerting"] = bool(spec["alerts"])
    return {
        "api_version": API_VERSION,
        "kind": KIND,
        "metadata": {
            "organization": organization,
            "observed_at": observed_at,
            "window_days": WINDOW_DAYS,
            "source_revision": source_revision,
        },
        "spec": spec,
    }


def _bytes_summary(value: float) -> str:
    return f"{value / GIB:.2f} GiB"


def render_markdown(report: dict[str, Any]) -> str:
    spec = report["spec"]
    lines = [
        f"### CI usage — {WINDOW_DAYS} day window",
        "",
        "| Measure | Current | Baseline | Change |",
        "|---|---|---|---|",
    ]

    def row(label: str, entry: dict[str, Any], render) -> str:
        if not entry["observed"]:
            return f"| {label} | not observed | not observed | — |"
        return (
            f"| {label} | {render(entry['current'])} | {render(entry['baseline'])} "
            f"| {entry['delta_ratio'] * 100:+.1f}% ({render(entry['delta_absolute'])}) |"
        )

    lines.append(row("Actions minutes", spec["minutes"], lambda v: f"{v:,.0f}"))
    lines.append(row("Job starts", spec["job_starts"], lambda v: f"{v:,.0f}"))
    lines.append(row("Artifact storage", spec["artifact_bytes"], _bytes_summary))
    cache = spec["cache_bytes"]
    limit = float(spec["cache_limit_bytes"])
    if cache["observed"] and limit > 0:
        lines.append(
            f"| Cache use | {_bytes_summary(cache['current'])} of "
            f"{_bytes_summary(limit)} | — | {cache['current'] / limit * 100:.1f}% of limit |"
        )
    lines.append("")
    if spec["alerts"]:
        lines.append("Alerting on: " + ", ".join(f"`{alert}`" for alert in spec["alerts"]))
    else:
        lines.append("No threshold exceeded.")
    return "\n".join(lines) + "\n"


def _request(path: str, token: str, api_base: str) -> Any | None:
    """Return decoded JSON, or None when the endpoint is unavailable.

    An unavailable measurement is recorded as not observed rather than as zero;
    a zero would look like a collapse in usage and could suppress a real alert.
    """
    request = urllib.request.Request(
        api_base.rstrip("/") + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except TRANSIENT_REQUEST_ERRORS:
        return None


def collect(organization: str, token: str, api_base: str) -> dict[str, Any]:
    """Best-effort collection; every field degrades to None independently."""
    usage = _request(f"/organizations/{organization}/settings/billing/usage", token, api_base)
    minutes = None
    if isinstance(usage, dict) and isinstance(usage.get("usageItems"), list):
        minutes = sum(
            float(item.get("quantity") or 0)
            for item in usage["usageItems"]
            if str(item.get("product", "")).lower() == "actions"
        )
    cache = _request(f"/orgs/{organization}/actions/cache/usage", token, api_base)
    cache_bytes = None
    if isinstance(cache, dict):
        cache_bytes = cache.get("total_active_caches_size_in_bytes")
    return {"minutes": minutes, "cache_bytes": cache_bytes}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown-output")
    parser.add_argument("--baseline", help="previous CiUsageReport JSON, when one exists")
    parser.add_argument(
        "--api-base", default=os.environ.get("GITHUB_API_URL", "https://api.github.com")
    )
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 1

    observed = collect(args.organization, token, args.api_base)
    previous: dict[str, Any] = {}
    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path is not None and baseline_path.is_file():
        try:
            previous = json.loads(baseline_path.read_text(encoding="utf-8"))["spec"]
        except BASELINE_DECODE_ERRORS:
            previous = {}

    def baseline_of(name: str) -> float | None:
        entry = previous.get(name)
        return float(entry["current"]) if isinstance(entry, dict) and "current" in entry else None

    report = build_report(
        organization=args.organization,
        source_revision=args.source_revision,
        observed_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        minutes=measurement(observed["minutes"], baseline_of("minutes")),
        job_starts=measurement(None, baseline_of("job_starts")),
        cache_bytes=measurement(observed["cache_bytes"], baseline_of("cache_bytes")),
        cache_limit_bytes=float(os.environ.get("GHCFG_CACHE_LIMIT_BYTES") or 10 * GIB),
        artifact_bytes=measurement(None, baseline_of("artifact_bytes")),
    )
    Path(args.output).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.markdown_output:
        Path(args.markdown_output).write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
