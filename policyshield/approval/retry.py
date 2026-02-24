"""Retry with exponential backoff for approval notifications."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


async def retry_with_backoff(
    fn: Callable[[], Awaitable[Any]],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Any:
    """Execute an async function with exponential backoff retry.

    Args:
        fn: Async callable to execute.
        max_retries: Maximum number of retries (not counting initial attempt).
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap in seconds.
        retryable_exceptions: Exception types that trigger retry.

    Returns:
        The return value of *fn*.

    Raises:
        The last exception if all retries are exhausted.
    """
    last_error: BaseException | None = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except retryable_exceptions as e:
            last_error = e
            if attempt == max_retries:
                break
            delay = min(base_delay * (2**attempt), max_delay)
            logger.warning(
                "Retry %d/%d after %.1fs: %s",
                attempt + 1,
                max_retries,
                delay,
                e,
            )
            await asyncio.sleep(delay)
    raise last_error  # type: ignore[misc]
