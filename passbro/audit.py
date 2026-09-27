"""Append caller-supplied metadata to a private JSON Lines file.

Audit does not filter or sanitize records. Callers must pass metadata only,
such as addresses, field names, argv, and decisions; never secret values.
"""

from collections import deque
from datetime import datetime
import json
import os
from pathlib import Path


def _ensure_private_directory(path):
    """Create missing directories with mode 0700; preserve existing modes."""
    try:
        os.mkdir(path, 0o700)
    except FileNotFoundError:
        parent = path.parent
        if parent == path:
            raise
        _ensure_private_directory(parent)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            if not path.is_dir():
                raise
        else:
            os.chmod(path, 0o700)
    except FileExistsError:
        if not path.is_dir():
            raise
    else:
        os.chmod(path, 0o700)


class Audit:
    """Append caller-supplied records to ``path`` without filtering.

    Callers must supply metadata only, and fields are serialized unchanged.
    """

    def __init__(self, path):
        self.path = Path(path).expanduser()

    def write(self, **record):
        audit_record = dict(record)
        audit_record["ts"] = datetime.now().astimezone().isoformat()
        line = (json.dumps(audit_record, ensure_ascii=False, allow_nan=False) + "\n").encode(
            "utf-8"
        )

        _ensure_private_directory(self.path.parent)

        # The daemon has one writer; O_APPEND places each record at EOF.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(line):
                offset += os.write(fd, line[offset:])
        finally:
            os.close(fd)


def recent_decisions(path, limit):
    """Return the last ``limit`` final run records from the log at ``path``.

    A record is final when it is a denial or carries the command exit code.
    """
    records = deque(maxlen=limit)
    try:
        with open(Path(path).expanduser(), encoding="utf-8") as log:
            for line in log:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict) or "decision" not in record:
                    continue
                if record["decision"] == "deny" or record.get("exit") is not None:
                    records.append(record)
    except FileNotFoundError:
        pass
    return list(records)
