"""Interactive approval prompts for secret requests."""

from datetime import datetime
import os
import select
import shlex
import shutil
import threading
import termios
import time
import unicodedata

from passbro.term import CYAN as _CYAN, DIM as _DIM
from passbro.term import GREEN as _GREEN, HEADER as _HEADER, RED as _RED
from passbro.term import YELLOW as _YELLOW, paint, status_line, use_color


_TIMEOUT = object()
_MAX_ANSWER_BYTES = 64
_LINE_SECONDS = 5
_MAX_WIDTH = 72
_LABEL_WIDTH = 11

IDLE_TEXT = "Waiting for requests. Type ? for commands, Ctrl+C to stop."

_CHOICES = (("n", "deny"), ("1", "allow once"), ("h", "allow for 1 hour"))

_OUTCOMES = {
    "deny": ("\u2717 denied", _RED),
    "once": ("\u2713 allowed once", _GREEN),
    "hour": ("\u2713 allowed for 1 hour", _GREEN),
    "timeout": ("\u2717 timed out - denied", _RED),
}


class Prompter:
    """Ask the owner to deny, allow once, or allow for an hour.

    ``request`` is a mapping containing ``pid``, ``parent_cmdline`` (an argv
    sequence or an already formatted string), ``cwd``, ``exe`` (the resolved
    executable path), ``why``, ``env`` (the requested variable-to-reference
    mapping), and ``argv`` (the exact command argument vector).
    """

    def __init__(self, input, output, timeout=120):
        if timeout < 0:
            raise ValueError("timeout must be non-negative")
        self.input = input
        self.output = output
        self.timeout = timeout
        self._lock = threading.Lock()
        self._count = 0
        self._color = self._use_color(output)

    def ask(self, request):
        """Return ``deny``, ``once``, or ``hour`` for a single request."""
        with self._lock:
            self._count += 1
            self.output.write(self._render(request))
            self.output.flush()
            self._flush_pending_input()
            deadline = time.monotonic() + self.timeout

            while True:
                answer = self._read_answer(deadline)
                if answer is _TIMEOUT:
                    self._write_outcome("timeout", newline=True)
                    return "deny"
                if answer is None:
                    return "deny"
                decision = {"n": "deny", "1": "once", "h": "hour"}.get(
                    answer.strip()
                )
                if decision is not None:
                    self._write_outcome(decision)
                    return decision
                line = status_line("?", "Enter n, 1 or h: ", _YELLOW, self._color)
                self.output.write(f"  {line}")
                self.output.flush()

    def notify_granted(self, request):
        """Show one dim line for a run approved by an existing hour grant."""
        with self._lock:
            stamp = datetime.now().strftime("%H:%M:%S")
            names = ", ".join(self._safe_text(name) for name in request["env"])
            argv = self._safe_text(shlex.join(request["argv"]))
            line = f"{stamp} auto-approved (1h grant) [{names}]: {argv}"
            self.output.write(f"  {self._paint(line, _DIM)}\n")
            self.output.flush()

    def status(self, symbol, text, code):
        """Show one progress line for the request that is being handled."""
        with self._lock:
            line = status_line(symbol, self._safe_text(text), code, self._color)
            self.output.write(f"  {line}\n")
            self.output.flush()

    def idle(self):
        """Close the current request block and show that the broker is idle."""
        with self._lock:
            width = min(shutil.get_terminal_size().columns, _MAX_WIDTH)
            self.output.write(self._paint("\u2500" * width, _DIM) + "\n")
            self.output.write(status_line("\u2022", IDLE_TEXT, _CYAN, self._color) + "\n")
            self.output.flush()

    def idle_command(self, handler, timeout):
        """Read one owner command line while no question is shown.

        Waits up to ``timeout`` seconds. The line is passed to ``handler``
        with the prompt lock held, so its output cannot interleave with a
        question. Returns False once input reaches EOF, otherwise True.
        """
        with self._lock:
            fd = self.input.fileno()
            readable, _, _ = select.select([fd], [], [], timeout)
            if not readable:
                return True
            line = self._read_answer(time.monotonic() + _LINE_SECONDS)
            if line is None:
                return False
            if line is _TIMEOUT:
                return True
            handler(line.strip())
            self.output.flush()
            return True

    def _write_outcome(self, outcome, newline=False):
        text, code = _OUTCOMES[outcome]
        mark, text = text.split(" ", 1)
        prefix = "\n" if newline else ""
        line = status_line(mark, text, code, self._color)
        self.output.write(f"{prefix}  {line}\n")
        self.output.flush()

    @staticmethod
    def _use_color(output):
        return use_color(output)

    def _paint(self, text, code):
        return paint(text, code, self._color)

    def _field(self, label, value, code=None):
        # Wrap long values under the value column so the table keeps its shape.
        label = self._paint(label.ljust(_LABEL_WIDTH), _DIM)
        room = max(self._width() - 2 - _LABEL_WIDTH - 1, 8)
        chunks = [value[i : i + room] for i in range(0, len(value), room)] or [""]
        if code is not None:
            chunks = [self._paint(chunk, code) for chunk in chunks]
        indent = " " * (2 + _LABEL_WIDTH + 1)
        return f"  {label} " + f"\n{indent}".join(chunks)

    @staticmethod
    def _width():
        return min(shutil.get_terminal_size().columns, _MAX_WIDTH)

    def _flush_pending_input(self):
        fd = self.input.fileno()
        if os.isatty(fd):
            termios.tcflush(fd, termios.TCIFLUSH)
            return

        while True:
            readable, _, _ = select.select([fd], [], [], 0)
            if not readable or not os.read(fd, 4096):
                return

    def _read_answer(self, deadline):
        fd = self.input.fileno()
        answer = bytearray()
        too_long = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _TIMEOUT
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                return _TIMEOUT

            byte = os.read(fd, 1)
            if not byte:
                return None
            if byte == b"\n":
                if too_long:
                    return ""
                return answer.decode("utf-8", errors="replace")
            if not too_long:
                answer.extend(byte)
                if len(answer) > _MAX_ANSWER_BYTES:
                    answer.clear()
                    too_long = True

    def _render(self, request):
        parent_cmdline = request["parent_cmdline"]
        if not isinstance(parent_cmdline, str):
            parent_cmdline = shlex.join(parent_cmdline)

        width = self._width()
        title = f" Secret request #{self._count}"
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " "
        gap = max(width - len(title) - len(stamp), 1)
        rule = self._paint("\u2501" * width, _HEADER)
        lines = [
            "",
            rule,
            self._paint(title, _HEADER) + " " * gap + self._paint(stamp, _DIM),
            rule,
            self._field("Reason", self._safe_text(request["why"])),
            self._field("Command", self._safe_text(shlex.join(request["argv"]))),
        ]
        label = "Secrets"
        for name, reference in request["env"].items():
            lines.append(
                self._field(
                    label,
                    f"{self._safe_text(name)} = {self._safe_text(reference)}",
                    _CYAN,
                )
            )
            label = ""
        if request.get("warning"):
            lines.extend(
                (
                    "",
                    "  "
                    + self._paint(
                        f"\u26a0 Warning: {self._safe_text(request['warning'])}",
                        _YELLOW,
                    ),
                )
            )
        lines.extend(
            (
                "",
                self._field("Executable", self._safe_text(request["exe"])),
                self._field("Directory", self._safe_text(request["cwd"])),
                self._field("Client PID", self._safe_text(request["pid"])),
                self._field("Parent", self._one_line(parent_cmdline, width), _DIM),
                "",
                "  "
                + "   ".join(
                    f"{self._paint(key, _CYAN)}: {text}"
                    for key, text in _CHOICES
                ),
                "  " + status_line("?", "Decision [n/1/h]: ", _YELLOW, self._color),
            )
        )
        return "\n".join(lines)

    def _one_line(self, value, width):
        # The full parent command line stays in the audit log.
        room = max(width - 2 - _LABEL_WIDTH - 1, 8)
        text = self._safe_text(value)
        return text if len(text) <= room else text[: room - 1] + "\u2026"

    @staticmethod
    def _safe_text(value):
        """Keep untrusted request text from changing terminal control state."""
        text = str(value)
        escaped = []
        for char in text:
            category = unicodedata.category(char)
            if category in {"Cc", "Cf", "Zl", "Zp", "Co", "Cn"}:
                codepoint = ord(char)
                if codepoint <= 0xff:
                    escaped.append(f"\\x{codepoint:02x}")
                elif codepoint <= 0xffff:
                    escaped.append(f"\\u{codepoint:04x}")
                else:
                    escaped.append(f"\\U{codepoint:08x}")
            else:
                escaped.append(char)
        return "".join(escaped)
