"""Time-limited grants for exact fields, command, cwd, and executable."""
import threading
import time


class Grants:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._grants = []
        self._lock = threading.Lock()

    def add(
        self, fields: frozenset, argv: tuple, cwd, exe, ttl, exe_identity=None
    ):
        fields = frozenset(fields)
        argv = tuple(argv)
        with self._lock:
            expires_at = self._clock() + ttl
            self._grants.append(
                (fields, argv, cwd, exe, exe_identity, expires_at)
            )

    def check(
        self, fields: frozenset, argv: tuple, cwd, exe, exe_identity=None
    ) -> bool:
        fields = frozenset(fields)
        argv = tuple(argv)
        with self._lock:
            now = self._clock()
            self._grants = [
                grant for grant in self._grants if grant[5] > now
            ]
            return any(
                grant_fields == fields
                and grant_argv == argv
                and grant_cwd == cwd
                and grant_exe == exe
                and grant_identity == exe_identity
                for (
                    grant_fields,
                    grant_argv,
                    grant_cwd,
                    grant_exe,
                    grant_identity,
                    _,
                ) in self._grants
            )

    def active(self):
        """Return ``(fields, argv, seconds_left)`` for unexpired grants."""
        with self._lock:
            now = self._clock()
            self._grants = [
                grant for grant in self._grants if grant[5] > now
            ]
            return [
                (grant[0], grant[1], grant[5] - now) for grant in self._grants
            ]

    def clear(self):
        """Revoke every grant and return how many were active."""
        with self._lock:
            now = self._clock()
            count = sum(1 for grant in self._grants if grant[5] > now)
            self._grants = []
            return count
