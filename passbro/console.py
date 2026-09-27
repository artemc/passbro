"""Owner commands typed in the broker terminal between questions."""

from datetime import datetime
import os
import shlex
import signal
import threading

from passbro import audit as audit_module
from passbro import term

_RECENT = 10
_HELP = (
    ("?", "show this help"),
    ("g", "list active 1-hour grants"),
    ("r", "revoke all grants"),
    ("l", f"show the last {_RECENT} decisions"),
    ("q", "stop passbro agent"),
)
_DECISIONS = {
    "deny": ("denied", term.RED),
    "once": ("once", term.GREEN),
    "hour": ("1 hour", term.GREEN),
}


class Console:
    def __init__(self, prompter, grants, log_path, output, stop=None):
        self.prompter = prompter
        self.grants = grants
        self.log_path = log_path
        self.output = output
        self.stop = stop or (lambda: os.kill(os.getpid(), signal.SIGINT))
        self._color = term.use_color(output)
        self._commands = {
            "?": self.help,
            "g": self.show_grants,
            "r": self.revoke,
            "l": self.show_recent,
            "q": self.quit,
        }

    def start(self):
        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()
        return thread

    def _loop(self):
        while self.prompter.idle_command(self.handle, timeout=0.2):
            pass

    def handle(self, line):
        if not line:
            return
        command = self._commands.get(line)
        if command is None:
            self._say(self._paint(f"Unknown command: {line!r}. Type ? for help.", term.YELLOW))
            return
        command()

    def _paint(self, text, code):
        return term.paint(text, code, self._color)

    def _say(self, text=""):
        self.output.write(f"{text}\n")

    def help(self):
        self._say("Commands (type a letter, then Enter):")
        for key, text in _HELP:
            self._say(f"  {key}  {text}")

    def show_grants(self):
        active = self.grants.active()
        if not active:
            self._say(self._paint("No active grants.", term.DIM))
            return
        self._say(f"Active grants ({len(active)}):")
        for number, (fields, argv, left) in enumerate(active, 1):
            minutes = max(int(left // 60), 1)
            self._say(
                f"  {number}. {self._paint(f'{minutes} min left', term.DIM)}  "
                f"{self._safe(shlex.join(argv))}"
            )
            self._say(
                f"     {self._paint(', '.join(sorted(self._safe(f) for f in fields)), term.CYAN)}"
            )

    def revoke(self):
        count = self.grants.clear()
        self._say(self._paint(f"✓ Revoked {count} grant(s).", term.GREEN))

    def show_recent(self):
        records = audit_module.recent_decisions(self.log_path, _RECENT)
        if not records:
            self._say(self._paint("No decisions yet.", term.DIM))
            return
        self._say(f"Last {len(records)} decisions:")
        for record in records:
            text, code = _DECISIONS.get(record["decision"], (str(record["decision"]), term.DIM))
            if record.get("granted"):
                text = "auto"
            stamp = self._stamp(record.get("ts"))
            argv = record.get("argv")
            command = shlex.join(argv) if isinstance(argv, list) else str(argv)
            self._say(
                f"  {self._paint(stamp, term.DIM)}  "
                f"{self._paint(text.ljust(7), code)} {self._safe(command)}"
            )

    def quit(self):
        self.stop()

    @staticmethod
    def _stamp(value):
        try:
            return datetime.fromisoformat(value).strftime("%m-%d %H:%M")
        except (TypeError, ValueError):
            return "?".ljust(11)

    @staticmethod
    def _safe(value):
        from passbro.prompt import Prompter

        return Prompter._safe_text(value)
