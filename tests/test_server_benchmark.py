"""Performance benchmarks for PolicyShield HTTP server.

Run with: pytest tests/test_server_benchmark.py -v -m benchmark
"""

import time

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from policyshield.core.models import RuleConfig, RuleSet, Verdict  # noqa: E402
from policyshield.server.app import create_app  # noqa: E402
from policyshield.shield.async_engine import AsyncShieldEngine  # noqa: E402


def _make_bench_engine() -> AsyncShieldEngine:
    rules = RuleSet(
        shield_name="bench",
        version=1,
        rules=[
            RuleConfig(
                id="block-exec",
                description="Block exec calls",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is not allowed",
            ),
        ],
    )
    return AsyncShieldEngine(rules)


@pytest.fixture
def bench_client() -> TestClient:
    engine = _make_bench_engine()
    app = create_app(engine)
    return TestClient(app)


@pytest.mark.benchmark
class TestServerPerformance:
    def test_check_latency_p99(self, bench_client: TestClient):
        """p99 latency for /check should be under 10ms."""
        latencies = []
        for _ in range(1000):
            start = time.perf_counter()
            resp = bench_client.post(
                "/api/v1/check",
                json={
                    "tool_name": "exec",
                    "args": {"command": "echo hello"},
                },
            )
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
            assert resp.status_code == 200

        latencies.sort()
        p99 = latencies[int(len(latencies) * 0.99)]
        p50 = latencies[int(len(latencies) * 0.50)]

        print(f"\n  p50={p50:.2f}ms  p99={p99:.2f}ms")
        assert p99 < 10, f"p99 latency {p99:.2f}ms exceeds 10ms limit"

    def test_health_latency(self, bench_client: TestClient):
        """Health check should be instant."""
        start = time.perf_counter()
        resp = bench_client.get("/api/v1/health")
        elapsed = (time.perf_counter() - start) * 1000
        assert resp.status_code == 200
        assert elapsed < 50, f"Health check took {elapsed:.2f}ms"
