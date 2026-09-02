"""CiUsageReport thresholds: both proportional and absolute growth are required."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from ci_usage_report import (  # noqa: E402
    GIB,
    build_report,
    evaluate_alerts,
    measurement,
    render_markdown,
)


def report(**overrides):
    quiet = {
        "minutes": measurement(100, 100),
        "job_starts": measurement(100, 100),
        "cache_bytes": measurement(1 * GIB, 1 * GIB),
        "cache_limit_bytes": 10 * GIB,
        "artifact_bytes": measurement(1 * GIB, 1 * GIB),
    }
    quiet.update(overrides)
    return build_report("mindclade", "a" * 40, "2026-09-02T00:00:00Z", **quiet)


class CiUsageReportTest(unittest.TestCase):
    def test_quiet_estate_raises_nothing(self):
        self.assertEqual(report()["spec"]["alerts"], [])
        self.assertFalse(report()["spec"]["alerting"])

    def test_each_threshold_requires_both_ratio_and_absolute_growth(self):
        # Ratio met, absolute not: +30% of 100 minutes is only +30, under the 60 floor.
        self.assertEqual(report(minutes=measurement(130, 100))["spec"]["alerts"], [])
        self.assertEqual(
            report(minutes=measurement(400, 100))["spec"]["alerts"], ["minutes_growth"]
        )
        # +20% of 100 starts is only +20, under the 25 floor.
        self.assertEqual(report(job_starts=measurement(120, 100))["spec"]["alerts"], [])
        self.assertEqual(
            report(job_starts=measurement(130, 100))["spec"]["alerts"], ["job_start_growth"]
        )
        # +50% of 1 GiB is only +0.5 GiB, under the 1 GiB floor.
        half = int(1.5 * GIB)
        self.assertEqual(report(artifact_bytes=measurement(half, 1 * GIB))["spec"]["alerts"], [])
        self.assertEqual(
            report(artifact_bytes=measurement(3 * GIB, 1 * GIB))["spec"]["alerts"],
            ["artifact_growth"],
        )

    def test_cache_alerts_on_utilization_not_growth(self):
        self.assertEqual(
            report(cache_bytes=measurement(8 * GIB, 1 * GIB))["spec"]["alerts"],
            ["cache_utilization"],
        )
        self.assertEqual(
            report(cache_bytes=measurement(int(7.9 * GIB), 1 * GIB))["spec"]["alerts"], []
        )

    def test_unobserved_measurements_never_alert(self):
        """A failed API call must not read as a collapse, nor suppress other alerts."""
        for name in ("minutes", "job_starts", "artifact_bytes", "cache_bytes"):
            with self.subTest(measurement=name):
                self.assertEqual(report(**{name: measurement(None, 100)})["spec"]["alerts"], [])

    def test_zero_baseline_does_not_divide_by_zero(self):
        self.assertEqual(report(minutes=measurement(500, 0))["spec"]["alerts"], [])

    def test_report_matches_its_published_schema(self):
        schema = json.loads(
            (ROOT / "schemas/v1/ci_usage_report.schema.json").read_text(encoding="utf-8")
        )
        document = report(minutes=measurement(400, 100))
        self.assertEqual(document["api_version"], schema["properties"]["api_version"]["const"])
        self.assertEqual(document["kind"], schema["properties"]["kind"]["const"])
        self.assertEqual(sorted(document), sorted(schema["required"]))
        self.assertEqual(
            sorted(document["spec"]), sorted(schema["$defs"]["spec"]["required"])
        )
        self.assertEqual(
            sorted(document["metadata"]), sorted(schema["$defs"]["metadata"]["required"])
        )
        for name in ("minutes", "job_starts", "cache_bytes", "artifact_bytes"):
            self.assertEqual(
                sorted(document["spec"][name]),
                sorted(schema["$defs"]["measurement"]["required"]),
                name,
            )
        allowed = set(schema["$defs"]["spec"]["properties"]["alerts"]["items"]["enum"])
        self.assertEqual(set(evaluate_alerts(document["spec"])) - allowed, set())

    def test_markdown_summary_reports_every_measure(self):
        summary = render_markdown(report(minutes=measurement(400, 100)))
        for expected in ("Actions minutes", "Job starts", "Artifact storage", "minutes_growth"):
            self.assertIn(expected, summary)
        self.assertIn("not observed", render_markdown(report(minutes=measurement(None, 100))))


if __name__ == "__main__":
    unittest.main()
