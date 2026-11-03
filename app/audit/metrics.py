"""Prometheus metrikaları. api /metrics-də, worker isə 9100 portunda göstərir."""

import time
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram

ALERTS = Counter(
    "alert2case_alerts_total", "Emal olunan alert-lər", ["alert_type", "action", "priority", "shadow"]
)
DUPLICATES = Counter("alert2case_duplicates_total", "Dedup ilə birləşən alert-lər", ["alert_type"])
STAGE = Histogram(
    "alert2case_stage_seconds",
    "Mərhələnin müddəti",
    ["stage"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60, 120),
)
TIME_TO_ACTION = Histogram(
    "alert2case_time_to_action_seconds",
    "received_at-dən hərəkətə qədər",
    ["alert_type"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800),
)
INTEL = Counter("alert2case_intel_results_total", "Provider nəticələri", ["provider", "status", "cached"])
NOTIFY = Counter("alert2case_notifications_total", "Bildirişlər", ["channel"])
DLQ_DEPTH = Gauge("alert2case_dlq_depth", "DLQ-dakı mesaj sayı", ["stream"])


@contextmanager
def timed(stage: str):
    t0 = time.perf_counter()
    try:
        yield
    finally:
        STAGE.labels(stage).observe(time.perf_counter() - t0)
