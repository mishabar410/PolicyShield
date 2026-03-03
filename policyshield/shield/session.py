"""Session manager for PolicyShield — thread-safe session state management."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from policyshield.core.models import PIIType, SessionState
from policyshield.shield.ring_buffer import EventRingBuffer
from policyshield.shield.session_backend import InMemorySessionBackend, SessionBackend


class SessionManager:
    """Thread-safe session state manager.

    Manages session lifecycle with TTL, max sessions, taint tracking,
    and tool call counting.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        max_sessions: int = 1000,
        backend: SessionBackend | None = None,
    ):
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._eviction_counter = 0
        self._eviction_every_n = 100
        self._backend = backend or InMemorySessionBackend(max_size=max_sessions, ttl_seconds=ttl_seconds)

    def _serialize_session(self, session: SessionState) -> dict:
        """Serialize SessionState to dict for backend storage."""
        return {
            "session_id": session.session_id,
            "created_at": session.created_at.isoformat(),
            "total_calls": session.total_calls,
            "tool_counts": dict(session.tool_counts),
            "taints": [t.value if hasattr(t, "value") else str(t) for t in session.taints],
        }

    def _sync_to_backend(self, session: SessionState) -> None:
        """Write-through: sync session state to backend."""
        try:
            self._backend.put(session.session_id, self._serialize_session(session))
        except Exception:
            pass  # fail-open on backend errors

    def get_or_create(self, session_id: str) -> SessionState:
        """Get an existing session or create a new one.

        Args:
            session_id: Session identifier.

        Returns:
            The SessionState for this session.
        """
        with self._lock:
            return self._get_or_create_unlocked(session_id)

    def _get_or_create_unlocked(self, session_id: str) -> SessionState:
        """Get or create session — caller must hold self._lock."""
        self._maybe_evict()
        if session_id in self._sessions:
            session = self._sessions[session_id]
            if self._is_expired(session):
                del self._sessions[session_id]
                self._backend.delete(session_id)
            else:
                session.last_accessed = datetime.now(timezone.utc)  # Issue #173
                return session

        # Evict oldest if at capacity
        if len(self._sessions) >= self._max_sessions:
            self._evict_oldest()

        session = SessionState(
            session_id=session_id,
            created_at=datetime.now(timezone.utc),
            event_buffer=EventRingBuffer(),
        )
        self._sessions[session_id] = session
        self._sync_to_backend(session)
        return session

    def get(self, session_id: str) -> SessionState | None:
        """Get a session by ID, or None if expired/missing.

        Args:
            session_id: Session identifier.

        Returns:
            SessionState or None.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session and self._is_expired(session):
                del self._sessions[session_id]
                self._backend.delete(session_id)
                return None
            if session:
                session.last_accessed = datetime.now(timezone.utc)  # Issue #173
            return session

    def record_call(self, session_id: str, tool_name: str) -> SessionState:
        """Atomically record a tool call for a session (Issue #102).

        This is the preferred way to increment counters — all operations
        happen under a single lock acquisition.

        Args:
            session_id: Session identifier.
            tool_name: Name of the tool called.

        Returns:
            Updated SessionState.
        """
        with self._lock:
            session = self._get_or_create_unlocked(session_id)
            session.increment(tool_name)
            self._sync_to_backend(session)
        return session

    def increment(self, session_id: str, tool_name: str) -> SessionState:
        """Increment tool call count for a session.

        Args:
            session_id: Session identifier.
            tool_name: Name of the tool called.

        Returns:
            Updated SessionState.
        """
        return self.record_call(session_id, tool_name)

    def get_event_buffer(self, session_id: str) -> EventRingBuffer:
        """Get the event buffer for a session (lazy-initializes if needed)."""
        with self._lock:
            session = self._get_or_create_unlocked(session_id)
            if session.event_buffer is None:
                session.event_buffer = EventRingBuffer()
            return session.event_buffer  # type: ignore[return-value]

    def add_taint(self, session_id: str, pii_type: PIIType) -> None:
        """Mark a session as tainted with a PII type.

        Args:
            session_id: Session identifier.
            pii_type: The PII type detected.
        """
        with self._lock:
            session = self._get_or_create_unlocked(session_id)
            session.taints.add(pii_type)
            self._sync_to_backend(session)

    def clear_taint(self, session_id: str) -> bool:
        """Clear PII taint from a session (thread-safe).

        Performs get + clear atomically under the manager lock,
        preventing race conditions with concurrent add_taint calls.

        Args:
            session_id: Session identifier.

        Returns:
            True if session was found and cleared, False if not found.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or self._is_expired(session):
                return False
            session.clear_taint()
            self._sync_to_backend(session)
            return True

    def remove(self, session_id: str) -> bool:
        """Remove a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if session was removed, False if not found.
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                self._backend.delete(session_id)
                return True
            return False

    def stats(self) -> dict:
        """Return session manager statistics.

        Returns:
            Dict with active_sessions, max_sessions, ttl_seconds.
        """
        with self._lock:
            self._evict_expired()
            backend_stats = self._backend.stats()
            return {
                "active_sessions": len(self._sessions),
                "max_sessions": self._max_sessions,
                "ttl_seconds": self._ttl_seconds,
                "backend": backend_stats,
            }

    def _is_expired(self, session: SessionState) -> bool:
        """Check if a session has exceeded its TTL (by last access)."""
        # Issue #173: Use last_accessed if available, otherwise created_at
        last_active = session.last_accessed or session.created_at
        return datetime.now(timezone.utc) - last_active > timedelta(seconds=self._ttl_seconds)

    def _maybe_evict(self) -> None:
        """Periodically evict expired sessions (amortized). Must be called with lock held."""
        self._eviction_counter += 1
        if self._eviction_counter < self._eviction_every_n:
            return
        self._eviction_counter = 0
        self._evict_expired()

    def _evict_expired(self) -> None:
        """Remove all expired sessions. Must be called with lock held."""
        expired = [sid for sid, s in self._sessions.items() if self._is_expired(s)]
        for sid in expired:
            del self._sessions[sid]
            self._backend.delete(sid)  # Issue #171: sync backend

    def _evict_oldest(self) -> None:
        """Remove the least-recently-used session. Must be called with lock held.

        Issue #91: Evicts by oldest creation time (LRU proxy), with fewest
        total calls as tiebreaker.
        """
        if not self._sessions:
            return
        lru_id = min(
            self._sessions,
            key=lambda sid: (
                self._sessions[sid].created_at,
                self._sessions[sid].total_calls,
            ),
        )
        del self._sessions[lru_id]
        self._backend.delete(lru_id)  # Issue #171: sync backend
