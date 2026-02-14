"""Engine-level performance benchmarks for PolicyShield.

Run with: pytest tests/test_benchmark.py -m benchmark -v
"""

from __future__ import annotations

import statistics
import time

import pytest

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine


def _make_bench_engine() -> ShieldEngine:
    rules = RuleSet(
        shield_name="benchmark",
        version=1,
        rules=[
            RuleConfig(
                id="block-rm",
                when={"tool": "rm"},
                then=Verdict.BLOCK,
                message="blocked",
            ),
            RuleConfig(
                id="allow-read",
                when={"tool": "read_file"},
                then=Verdict.ALLOW,
            ),
            RuleConfig(
                id="redact-pii",
                when={"tool": "send_email"},
                then=Verdict.REDACT,
            ),
        ],
    )
    return ShieldEngine(rules)


@pytest.mark.benchmark
class TestSyncBenchmark:
    def test_p99_under_5ms(self):
        """Sync engine p99 latency must be < 5ms."""
        engine = _make_bench_engine()
        latencies: list[float] = []

        # Warmup
        for _ in range(100):
            engine.check("read_file", {"path": "/tmp/x"})

        # Measure
        for _ in range(1000):
            start = time.perf_counter()
            engine.check("read_file", {"path": "/tmp/hello.txt"})
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)

        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        median = statistics.median(latencies)
        mean = statistics.mean(latencies)

        print(f"\nSync engine: mean={mean:.2f}ms, median={median:.2f}ms, p99={p99:.2f}ms")
        assert p99 < 5.0, f"p99 = {p99:.2f}ms exceeds 5ms target"

    def test_block_p99_under_5ms(self):
        """Sync engine BLOCK verdict p99 must be < 5ms."""
        engine = _make_bench_engine()
        latencies: list[float] = []

        for _ in range(100):
            engine.check("rm", {"path": "/"})

        for _ in range(1000):
            start = time.perf_counter()
            engine.check("rm", {"path": "/"})
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)

        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        print(f"\nSync BLOCK: p99={p99:.2f}ms")
        assert p99 < 5.0, f"p99 = {p99:.2f}ms exceeds 5ms target"


@pytest.mark.benchmark
class TestAsyncBenchmark:
    @pytest.mark.asyncio
    async def test_async_p99_under_10ms(self):
        """Async engine p99 latency must be < 10ms (includes thread overhead)."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules = RuleSet(
            shield_name="benchmark",
            version=1,
            rules=[
                RuleConfig(
                    id="allow-read",
                    when={"tool": "read_file"},
                    then=Verdict.ALLOW,
                ),
            ],
        )
        engine = AsyncShieldEngine(rules)

        # Warmup
        for _ in range(50):
            await engine.check("read_file", {"path": "/tmp/x"})

        # Measure
        latencies: list[float] = []
        for _ in range(500):
            start = time.perf_counter()
            await engine.check("read_file", {"path": "/tmp/hello.txt"})
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)

        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        print(f"\nAsync engine: p99={p99:.2f}ms")
        assert p99 < 10.0, f"Async p99 = {p99:.2f}ms exceeds 10ms target"
