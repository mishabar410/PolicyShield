"""OpenTelemetry exporter for PolicyShield.

Exposes spans (traces) and counters/histograms (metrics) for every shield
check.  The module is a **no-op** when the OpenTelemetry SDK is not installed,
so the dependency stays truly optional.
"""

from __future__ import annotations

import logging
from typing import Any

from policyshield.core.models import ShieldResult, Verdict

logger = logging.getLogger("policyshield")

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.trace import StatusCode

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


class OTelExporter:
    """OpenTelemetry exporter for PolicyShield.

    Creates spans and metrics for each shield check.
    Gracefully degrades if OTel SDK is not installed — all methods become
    no-ops.

    Usage::

        exporter = OTelExporter(service_name="my-app")
        engine = ShieldEngine(rules, otel_exporter=exporter)
    """

    def __init__(
        self,
        service_name: str = "policyshield",
        endpoint: str | None = None,  # noqa: ARG002 — reserved for OTLP config
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled and HAS_OTEL
        self._service_name = service_name

        if not self._enabled:
            if enabled and not HAS_OTEL:
                logger.warning(
                    "OpenTelemetry SDK not installed — OTel export disabled. "
                    "Install with: pip install policyshield[otel]"
                )
            self._tracer = None
            self._meter = None
            self._counter_total = None
            self._counter_blocked = None
            self._counter_pii = None
            self._histogram_latency = None
            return

        # Tracer
        self._tracer = otel_trace.get_tracer(service_name)

        # Meter (metrics)
        self._meter = otel_metrics.get_meter(service_name)

        self._counter_total = self._meter.create_counter(
            name="policyshield.checks.total",
            description="Total number of shield checks",
        )
        self._counter_blocked = self._meter.create_counter(
            name="policyshield.checks.blocked",
            description="Number of blocked shield checks",
        )
        self._counter_pii = self._meter.create_counter(
            name="policyshield.pii.detected",
            description="Number of PII detections",
        )
        self._histogram_latency = self._meter.create_histogram(
            name="policyshield.checks.latency",
            description="Shield check latency in milliseconds",
            unit="ms",
        )

    @property
    def enabled(self) -> bool:
        """Return whether OTel export is active."""
        return self._enabled

    def on_check_start(
        self,
        tool_name: str,
        session_id: str,
        args: dict | None = None,  # noqa: ARG002
    ) -> Any:
        """Start a span for a check operation.

        Returns:
            Span context (opaque object), or None if disabled.
        """
        if not self._enabled or self._tracer is None:
            return None

        span = self._tracer.start_span("policyshield.check")
        span.set_attribute("tool.name", tool_name)
        span.set_attribute("session.id", session_id)
        return span

    def on_check_end(
        self,
        span_context: Any,
        result: ShieldResult,
        latency_ms: float,
    ) -> None:
        """End the span, set attributes, and record metrics."""
        if not self._enabled:
            return

        # Metrics
        verdict_str = result.verdict.value
        tool_name = ""

        if span_context is not None:
            # Extract tool name from span attributes if available
            if hasattr(span_context, "attributes"):
                tool_name = span_context.attributes.get("tool.name", "")
            span_context.set_attribute("verdict", verdict_str)
            if result.rule_id:
                span_context.set_attribute("rule.id", result.rule_id)

            pii_detected = len(result.pii_matches) > 0
            span_context.set_attribute("pii.detected", pii_detected)
            if pii_detected:
                pii_types = [m.pii_type.value for m in result.pii_matches]
                span_context.set_attribute("pii.types", pii_types)
                span_context.add_event("pii_found", {"pii_types": str(pii_types)})

            # Status
            if result.verdict == Verdict.BLOCK:
                span_context.set_status(StatusCode.ERROR, result.message)
            else:
                span_context.set_status(StatusCode.OK)

            span_context.end()

        # Record counter and histogram
        labels = {"tool": tool_name, "verdict": verdict_str}
        if self._counter_total:
            self._counter_total.add(1, labels)
        if self._histogram_latency:
            self._histogram_latency.record(latency_ms, labels)

        if result.verdict == Verdict.BLOCK and self._counter_blocked:
            self._counter_blocked.add(1, {"tool": tool_name, "rule_id": result.rule_id or ""})

        if result.pii_matches and self._counter_pii:
            for m in result.pii_matches:
                self._counter_pii.add(1, {"pii_type": m.pii_type.value})

    def shutdown(self) -> None:
        """Flush and shutdown exporters."""
        if not self._enabled:
            return
        # TracerProvider and MeterProvider shutdown are typically handled
        # at the application level, but we expose this for completeness.
        try:
            provider = otel_trace.get_tracer_provider()
            if hasattr(provider, "shutdown"):
                provider.shutdown()
        except Exception:
            pass
