"""Dashboard backend — FastAPI REST API + WebSocket for live verdicts."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def create_dashboard_app(
    trace_dir: str | Path = "./traces",
    engine: Any = None,
):
    """Create and return a FastAPI app for the dashboard.

    Args:
        trace_dir: Path to the JSONL trace directory.
        engine: Optional AsyncShieldEngine or ShieldEngine for rules/management APIs.
    """
    try:
        from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
        from fastapi.responses import FileResponse, HTMLResponse
        from starlette.middleware.cors import CORSMiddleware
    except ImportError:
        raise ImportError("Dashboard requires 'fastapi'. Install with: pip install policyshield[dashboard]")

    from policyshield import __version__

    trace_dir = Path(trace_dir)
    app = FastAPI(title="PolicyShield Dashboard", version=__version__)

    # Allow all origins for dashboard (development-friendly)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/api/metrics")
    def get_metrics():
        from policyshield.trace.aggregator import TraceAggregator

        if not trace_dir.exists():
            return {"error": "Trace directory not found"}
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        return result.to_dict()

    @app.get("/api/metrics/verdicts")
    def get_verdicts():
        from policyshield.trace.aggregator import TraceAggregator

        if not trace_dir.exists():
            return {"error": "Trace directory not found"}
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        return result.verdict_breakdown.to_dict()

    @app.get("/api/metrics/tools")
    def get_tools():
        from policyshield.trace.aggregator import TraceAggregator

        if not trace_dir.exists():
            return {"error": "Trace directory not found"}
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        return [t.to_dict() for t in result.top_tools]

    @app.get("/api/metrics/pii")
    def get_pii():
        from policyshield.trace.aggregator import TraceAggregator

        if not trace_dir.exists():
            return {"error": "Trace directory not found"}
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        return [p.to_dict() for p in result.pii_heatmap]

    @app.get("/api/metrics/cost")
    def get_cost(model: str = "gpt-4o"):
        from policyshield.trace.cost import CostEstimator

        if not trace_dir.exists():
            return {"error": "Trace directory not found"}
        estimator = CostEstimator(model=model)
        est = estimator.estimate_from_traces(trace_dir)
        return est.to_dict()

    # ── Trace search endpoint ──
    @app.get("/api/traces/search")
    def search_traces(
        tool: Optional[str] = Query(None),
        verdict: Optional[str] = Query(None),
        session_id: Optional[str] = Query(None),
        text: Optional[str] = Query(None),
        rule_id: Optional[str] = Query(None),
        pii_type: Optional[str] = Query(None),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        from policyshield.trace.search import SearchQuery, TraceSearchEngine

        if not trace_dir.exists():
            return {"total": 0, "records": []}
        se = TraceSearchEngine(trace_dir)
        q = SearchQuery(
            tool=tool,
            verdict=verdict,
            session_id=session_id,
            text=text,
            rule_id=rule_id,
            pii_type=pii_type,
            limit=limit,
            offset=offset,
        )
        result = se.search(q)
        return {"total": result.total, "records": result.records}

    # ── Rules endpoint ──
    @app.get("/api/rules")
    def get_rules():
        if engine is None:
            return {"rules": [], "error": "No engine connected"}
        try:
            ruleset = engine.rules
            rules_list = []
            for r in ruleset.rules:
                rule_dict: dict[str, Any] = {"id": r.id, "then": r.then.value, "severity": r.severity}
                if hasattr(r, "enabled"):
                    rule_dict["enabled"] = r.enabled
                if hasattr(r, "priority"):
                    rule_dict["priority"] = r.priority
                if hasattr(r, "message") and r.message:
                    rule_dict["message"] = r.message
                # Extract tool from when clause
                when = r.when
                if hasattr(when, "tool"):
                    rule_dict["tool"] = when.tool
                if hasattr(when, "args_match") and when.args_match:
                    rule_dict["args_match"] = str(when.args_match)
                rules_list.append(rule_dict)
            return {"rules": rules_list, "count": len(rules_list)}
        except Exception as e:
            logger.error("Failed to load rules: %s", e)
            return {"rules": [], "error": str(e)}

    # WebSocket for live verdict stream
    app.state.ws_clients = set()

    @app.websocket("/ws/verdicts")
    async def ws_verdicts(websocket: WebSocket):
        await websocket.accept()
        app.state.ws_clients.add(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            app.state.ws_clients.discard(websocket)

    async def broadcast_verdict(verdict: dict) -> None:
        """Broadcast a verdict to all connected WebSocket clients."""
        dead = set()
        for ws in list(app.state.ws_clients):
            try:
                await ws.send_json(verdict)
            except Exception:
                dead.add(ws)
        app.state.ws_clients -= dead

    app.broadcast_verdict = broadcast_verdict  # type: ignore

    # Serve static frontend
    static_dir = Path(__file__).parent / "static"

    @app.get("/")
    def index():
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return HTMLResponse("<h1>PolicyShield Dashboard</h1><p>Frontend not found.</p>")

    return app


class LiveTraceWatcher:
    """Watches a trace directory for new entries and broadcasts via WebSocket."""

    def __init__(self, trace_dir: str | Path, app) -> None:
        self._trace_dir = Path(trace_dir)
        self._app = app
        self._positions: dict[Path, int] = {}
        self._running = False

    async def start(self, interval: float = 1.0) -> None:
        """Start watching for new trace entries."""
        self._running = True
        while self._running:
            await self._check_new_entries()
            await asyncio.sleep(interval)

    def stop(self) -> None:
        self._running = False

    async def _check_new_entries(self) -> None:
        if not self._trace_dir.exists():
            return
        current_files = set()
        for fp in sorted(self._trace_dir.glob("*.jsonl")):
            current_files.add(fp)
            pos = self._positions.get(fp, 0)
            try:
                with open(fp) as f:
                    f.seek(pos)
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                record = json.loads(line)
                                await self._app.broadcast_verdict(record)
                            except json.JSONDecodeError:
                                pass
                    self._positions[fp] = f.tell()
            except OSError:
                pass
        # Prune positions for files that no longer exist (e.g. rotated/deleted)
        stale = set(self._positions.keys()) - current_files
        for fp in stale:
            del self._positions[fp]
