"""OpenTelemetry tracing + metrics. Everything degrades to a no-op when no endpoint is configured.

Set OTEL_EXPORTER_OTLP_ENDPOINT (e.g. http://localhost:4318) to export spans and metrics.
"""
from __future__ import annotations

import contextlib
import os
import time
from typing import Iterator

_tracer = None
_meter = None
_instruments: dict = {}


def init(service_name: str = "proctor", endpoint: str | None = None, export_interval_ms: int = 2000) -> bool:
    """Configure exporters. Returns True if OTLP export is active."""
    global _tracer, _meter
    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        return False
    res = Resource.create({"service.name": service_name})
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.view import ExplicitBucketHistogramAggregation, View
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        tp = TracerProvider(resource=res)
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint.rstrip("/") + "/v1/traces")))
        trace.set_tracer_provider(tp)
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=endpoint.rstrip("/") + "/v1/metrics"),
            export_interval_millis=export_interval_ms)
        # OTel default buckets are 0..10000 in raw units; ours are seconds, so give them sub-ms resolution.
        secs = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        views = [View(instrument_name=n, aggregation=ExplicitBucketHistogramAggregation(secs))
                 for n in ("proctor_step_duration", "proctor_env_reset_duration")]
        mp = MeterProvider(resource=res, metric_readers=[reader], views=views)
        metrics.set_meter_provider(mp)
    _tracer = trace.get_tracer("proctor")
    _meter = metrics.get_meter("proctor")
    _instruments["steps"] = _meter.create_counter("proctor_steps", description="env steps")
    _instruments["step_dur"] = _meter.create_histogram("proctor_step_duration", unit="s",
                                                       description="wall time of one env.step()")
    _instruments["episodes"] = _meter.create_counter("proctor_episodes", description="finished episodes")
    _instruments["attempts"] = _meter.create_counter("proctor_exploit_attempts", description="red-team episodes")
    _instruments["cheats"] = _meter.create_counter("proctor_exploit_successes",
                                                   description="episodes with reward>0 and oracle=unsolved")
    _instruments["blocked"] = _meter.create_counter("proctor_blocked_attempts",
                                                    description="denied syscalls / containment events")
    _instruments["startup"] = _meter.create_histogram("proctor_env_reset_duration", unit="s",
                                                      description="env.reset() wall time")
    return bool(endpoint)


@contextlib.contextmanager
def span(name: str, parent=None, **attrs) -> Iterator[None]:
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name, context=parent,
                                       attributes={k: v for k, v in attrs.items() if v is not None}):
        yield


def start_span(name: str, **attrs):
    """Open a long-lived span (e.g. one per episode). Returns (span, context) to pass as `parent=`."""
    if _tracer is None:
        return None, None
    from opentelemetry import trace
    s = _tracer.start_span(name, attributes={k: v for k, v in attrs.items() if v is not None})
    return s, trace.set_span_in_context(s)


def end_span(s, **attrs) -> None:
    if s is None:
        return
    for k, v in attrs.items():
        if v is not None:
            s.set_attribute(k, v)
    s.end()


def add_event(name: str, **attrs) -> None:
    if _tracer is None:
        return
    from opentelemetry import trace
    trace.get_current_span().add_event(name, {k: v for k, v in attrs.items() if v is not None})


def set_attrs(**attrs) -> None:
    if _tracer is None:
        return
    from opentelemetry import trace
    s = trace.get_current_span()
    for k, v in attrs.items():
        if v is not None:
            s.set_attribute(k, v)


def count(name: str, value: int = 1, **labels) -> None:
    inst = _instruments.get(name)
    if inst is not None:
        inst.add(value, labels)


def observe(name: str, value: float, **labels) -> None:
    inst = _instruments.get(name)
    if inst is not None:
        inst.record(value, labels)


class Timer:
    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.dt = time.perf_counter() - self.t
