"""Terminal styling shared by the owner-facing output."""

import os

DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
CYAN = "36"
HEADER = "36"


def use_color(stream):
    """Follow the NO_COLOR convention and colour only real terminals."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    try:
        return os.isatty(stream.fileno())
    except (AttributeError, OSError, ValueError):
        return False


def paint(text, code, enabled):
    if not enabled:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def status_line(mark, text, code, enabled):
    """One owner-facing status line: coloured mark, plain text."""
    return f"{paint(mark, code, enabled)} {text}"
