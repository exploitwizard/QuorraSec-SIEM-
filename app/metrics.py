# app/metrics.py
"""
Prometheus metrics definitions for Courra-Sec.

Imported by main.py when Config.METRICS_ENABLED is True.
All counters/histograms are module-level singletons so they survive
multiple imports without double-registration errors.
"""

try:
    from prometheus_client import Counter, Histogram, Gauge, REGISTRY

    # ------------------------------------------------------------------
    # HTTP request instrumentation
    # ------------------------------------------------------------------
    HTTP_REQUESTS_TOTAL = Counter(
        "courra-sec_http_requests_total",
        "Total HTTP requests handled by Courra-Sec",
        ["method", "endpoint", "status_code"],
    )

    HTTP_REQUEST_DURATION = Histogram(
        "courra-sec_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )

    # ------------------------------------------------------------------
    # Ingest pipeline
    # ------------------------------------------------------------------
    INGEST_EVENTS_TOTAL = Counter(
        "courra-sec_ingest_events_total",
        "Total security events ingested (HTTP + WebSocket)",
        ["transport"],   # "http" or "websocket"
    )

    INGEST_ERRORS_TOTAL = Counter(
        "courra-sec_ingest_errors_total",
        "Total ingest errors",
    )

    # ------------------------------------------------------------------
    # Detection / alerts
    # ------------------------------------------------------------------
    RULES_TRIGGERED_TOTAL = Counter(
        "courra-sec_rules_triggered_total",
        "Total detection rule triggers",
        ["rule_name", "severity"],
    )

    ALERTS_CREATED_TOTAL = Counter(
        "courra-sec_alerts_created_total",
        "Total alerts created",
        ["severity", "alert_type"],
    )

    ML_ANOMALIES_TOTAL = Counter(
        "courra-sec_ml_anomalies_total",
        "Total ML anomaly detections",
        ["severity"],
    )

    # ------------------------------------------------------------------
    # System state gauges
    # ------------------------------------------------------------------
    LOGS_IN_DB = Gauge(
        "courra-sec_logs_in_db_total",
        "Total log entries stored in the database",
    )

    ATTACKS_IN_DB = Gauge(
        "courra-sec_attacks_in_db_total",
        "Total attack records stored in the database",
    )

    BLOCKED_IPS = Gauge(
        "courra-sec_blocked_ips_total",
        "Number of currently blocked IP addresses",
    )

    WS_CONNECTED = Gauge(
        "courra-sec_ws_connected",
        "1 if the Block Fortress WebSocket connection is active, 0 otherwise",
    )

    PROMETHEUS_AVAILABLE = True

except ImportError:
    PROMETHEUS_AVAILABLE = False

    # Provide no-op stubs so callers never need to guard with if/else
    class _Noop:
        def labels(self, **_):    return self
        def inc(self, *_, **__):  pass
        def observe(self, *_):    pass
        def set(self, *_):        pass
        def time(self):
            import contextlib
            return contextlib.nullcontext()

    _noop = _Noop()
    HTTP_REQUESTS_TOTAL     = _noop
    HTTP_REQUEST_DURATION   = _noop
    INGEST_EVENTS_TOTAL     = _noop
    INGEST_ERRORS_TOTAL     = _noop
    RULES_TRIGGERED_TOTAL   = _noop
    ALERTS_CREATED_TOTAL    = _noop
    ML_ANOMALIES_TOTAL      = _noop
    LOGS_IN_DB              = _noop
    ATTACKS_IN_DB           = _noop
    BLOCKED_IPS             = _noop
    WS_CONNECTED            = _noop
