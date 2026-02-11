"""Example: AsyncShieldEngine usage."""

from __future__ import annotations

import asyncio

from policyshield.shield.async_engine import AsyncShieldEngine


async def main() -> None:
    engine = AsyncShieldEngine("./policies/rules.yaml")

    # Basic check
    result = await engine.check("exec", {"cmd": "rm -rf /"})
    print(f"exec → {result.verdict.value}: {result.message}")

    # Concurrent checks
    tasks = [
        engine.check("read_file", {"path": "/tmp/log"}),
        engine.check("exec", {"cmd": "ls"}),
        engine.check("web_fetch", {"url": "https://example.com"}),
    ]
    results = await asyncio.gather(*tasks)
    for r in results:
        print(f"  → {r.verdict.value}: {r.message}")


if __name__ == "__main__":
    asyncio.run(main())
