#!/usr/bin/env python3
"""Verify TypeScript SDK types match Python API models.

Extracts field names from Pydantic models (server/models.py) and
TypeScript interfaces (plugins/openclaw/src/types.ts), then reports
any mismatches. Returns exit code 1 on mismatch.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_MODELS = ROOT / "policyshield" / "server" / "models.py"
TS_TYPES = ROOT / "plugins" / "openclaw" / "src" / "types.ts"

# Map Python model names → TypeScript type names (where they differ)
NAME_MAP: dict[str, str] = {
    "CheckRequest": "CheckRequest",
    "CheckResponse": "CheckResponse",
    "PostCheckRequest": "PostCheckRequest",
    "PostCheckResponse": "PostCheckResponse",
    "ConstraintsResponse": "ConstraintsResponse",
    "ApprovalStatusResponse": "ApprovalStatusResponse",
}


def extract_python_fields(path: Path) -> dict[str, set[str]]:
    """Extract field names from Pydantic BaseModel classes."""
    tree = ast.parse(path.read_text())
    models: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            fields: set[str] = set()
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    fields.add(item.target.id)
            if fields:
                models[node.name] = fields
    return models


def extract_ts_fields(path: Path) -> dict[str, set[str]]:
    """Extract field names from TypeScript type/interface declarations."""
    content = path.read_text()
    types: dict[str, set[str]] = {}
    # Match: export type Foo = { ... } or type Foo = { ... }
    for match in re.finditer(r"(?:export\s+)?type\s+(\w+)\s*=\s*\{([^}]+)\}", content):
        name = match.group(1)
        body = match.group(2)
        fields = set(re.findall(r"(\w+)\s*[?]?\s*:", body))
        types[name] = fields
    return types


def compare(py_models: dict[str, set[str]], ts_types: dict[str, set[str]]) -> list[str]:
    """Compare Python and TS models. Return list of error messages."""
    errors = []
    for py_name, ts_name in NAME_MAP.items():
        py_fields = py_models.get(py_name)
        ts_fields = ts_types.get(ts_name)

        if py_fields is None:
            errors.append(f"Python model {py_name} not found in {PY_MODELS.name}")
            continue
        if ts_fields is None:
            errors.append(f"TypeScript type {ts_name} not found in {TS_TYPES.name}")
            continue

        # Check Python fields missing from TS
        for field in py_fields:
            # Convert python snake_case to check if it exists in TS
            if field not in ts_fields:
                errors.append(f"{py_name}.{field}: missing in TypeScript {ts_name}")

        # Check TS fields missing from Python
        for field in ts_fields:
            if field not in py_fields:
                errors.append(f"{ts_name}.{field}: missing in Python {py_name}")

    return errors


def main() -> int:
    if not PY_MODELS.exists():
        print(f"❌ Python models not found: {PY_MODELS}")
        return 1
    if not TS_TYPES.exists():
        print(f"❌ TypeScript types not found: {TS_TYPES}")
        return 1

    py = extract_python_fields(PY_MODELS)
    ts = extract_ts_fields(TS_TYPES)

    print(f"Python models: {', '.join(sorted(py.keys()))}")
    print(f"TypeScript types: {', '.join(sorted(ts.keys()))}")
    print()

    errors = compare(py, ts)
    if errors:
        print(f"❌ SDK sync errors ({len(errors)}):")
        for e in errors:
            print(f"  • {e}")
        return 1

    print(f"✅ SDK types in sync ({len(NAME_MAP)} models checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
