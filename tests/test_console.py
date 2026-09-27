import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from passbro import audit
from passbro.console import Console
from passbro.grants import Grants
from passbro.prompt import Prompter


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "log.jsonl"
        self.clock = _Clock()
        self.grants = Grants(clock=self.clock)
        self.output = io.StringIO()
        self.stopped = []
        self.console = Console(
            None, self.grants, self.log, self.output, stop=lambda: self.stopped.append(1)
        )

    def _write_log(self, *records):
        with open(self.log, "w", encoding="utf-8") as log:
            for record in records:
                log.write(json.dumps(record) + "\n")

    def test_help_lists_every_command(self):
        self.console.handle("?")
        for key in ("?", "g", "r", "l", "q"):
            self.assertIn(f"  {key}  ", self.output.getvalue())

    def test_unknown_command_points_to_help(self):
        self.console.handle("x")
        self.assertIn("Unknown command: 'x'. Type ? for help.", self.output.getvalue())

    def test_empty_line_is_ignored(self):
        self.console.handle("")
        self.assertEqual(self.output.getvalue(), "")

    def test_grants_show_command_fields_and_minutes_left(self):
        self.grants.add({"porkbun/api-key/password"}, ("sh", "-c", "echo $X"), "/w", "/bin/sh", ttl=3600)
        self.clock.now += 600

        self.console.handle("g")

        output = self.output.getvalue()
        self.assertIn("Active grants (1):", output)
        self.assertIn("50 min left", output)
        self.assertIn("sh -c 'echo $X'", output)
        self.assertIn("porkbun/api-key/password", output)

    def test_expired_grants_are_not_listed(self):
        self.grants.add({"a/b/c"}, ("true",), "/w", "/bin/true", ttl=10)
        self.clock.now += 11

        self.console.handle("g")

        self.assertIn("No active grants.", self.output.getvalue())

    def test_revoke_clears_grants(self):
        self.grants.add({"a/b/c"}, ("true",), "/w", "/bin/true", ttl=3600)

        self.console.handle("r")

        self.assertIn("Revoked 1 grant(s).", self.output.getvalue())
        self.assertFalse(self.grants.check({"a/b/c"}, ("true",), "/w", "/bin/true"))

    def test_recent_shows_final_records_only(self):
        self._write_log(
            {"op": "ls", "ts": "2026-09-27T10:00:00-04:00"},
            {"decision": "deny", "exit": None, "granted": False, "argv": ["a"], "ts": "2026-09-27T10:01:00-04:00"},
            {"decision": "once", "exit": None, "granted": False, "argv": ["b"], "ts": "2026-09-27T10:02:00-04:00"},
            {"decision": "once", "exit": 0, "granted": False, "argv": ["b"], "ts": "2026-09-27T10:02:01-04:00"},
            {"decision": "hour", "exit": 3, "granted": True, "argv": ["c\x1b"], "ts": "2026-09-27T10:03:00-04:00"},
        )

        self.console.handle("l")

        lines = self.output.getvalue().splitlines()
        self.assertEqual(lines[0], "Last 3 decisions:")
        self.assertEqual(lines[1], "  09-27 10:01  denied  a")
        self.assertEqual(lines[2], "  09-27 10:02  once    b")
        self.assertEqual(lines[3], "  09-27 10:03  auto    'c\\x1b'")

    def test_recent_without_log(self):
        self.console.handle("l")
        self.assertIn("No decisions yet.", self.output.getvalue())

    def test_recent_keeps_only_last_records(self):
        self._write_log(
            *(
                {"decision": "deny", "argv": [str(n)], "ts": "2026-09-27T10:00:00"}
                for n in range(15)
            )
        )
        records = audit.recent_decisions(self.log, 10)
        self.assertEqual([r["argv"][0] for r in records], [str(n) for n in range(5, 15)])

    def test_quit_calls_stop(self):
        self.console.handle("q")
        self.assertEqual(self.stopped, [1])


class IdleCommandTests(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        self.input = os.fdopen(self.read_fd, "rb", buffering=0)
        self.output = io.StringIO()
        self.prompter = Prompter(self.input, self.output, timeout=1)

    def tearDown(self):
        self.input.close()
        try:
            os.close(self.write_fd)
        except OSError:
            pass

    def test_line_is_passed_to_handler(self):
        lines = []
        os.write(self.write_fd, b" g \n")
        self.assertTrue(self.prompter.idle_command(lines.append, timeout=1))
        self.assertEqual(lines, ["g"])

    def test_no_input_returns_without_calling_handler(self):
        lines = []
        self.assertTrue(self.prompter.idle_command(lines.append, timeout=0.01))
        self.assertEqual(lines, [])

    def test_eof_stops_the_loop(self):
        os.close(self.write_fd)
        self.assertFalse(self.prompter.idle_command(lambda line: None, timeout=1))


if __name__ == "__main__":
    unittest.main()
