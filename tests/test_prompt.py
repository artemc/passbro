import io
import os
import select
import termios
import threading
import time
import unittest
from unittest.mock import patch

from passbro.prompt import Prompter


class _PromptOutput(io.StringIO):
    """Pipe answers only after the corresponding prompt has been flushed."""

    _PROMPT_MARKER = "Decision [n/1/h]: "

    def __init__(self, write_fd):
        super().__init__()
        self.write_fd = write_fd
        self.responses = []
        self.question_count = 0
        self.answer_prompt_count = 0
        self.events = []

    def write(self, value):
        result = super().write(value)
        self.question_count += value.count(self._PROMPT_MARKER)
        if self._PROMPT_MARKER in value:
            self.answer_prompt_count += value.count(self._PROMPT_MARKER)
            self.events.append("question_written")
        self.answer_prompt_count += value.count("Enter n, 1 or h: ")
        return result

    def flush(self):
        result = super().flush()
        self.events.append("output_flushed")
        return result


class PrompterTests(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        self.input = os.fdopen(self.read_fd, "rb", buffering=0)
        self.output = _PromptOutput(self.write_fd)
        self.request = {
            "pid": 4321,
            "parent_cmdline": ["python3", "agent script.py"],
            "cwd": "/tmp/work",
            "exe": "/usr/bin/renew",
            "why": "renew the domain",
            "env": {"PORKBUN_KEY": "porkbun/api-key/password"},
            "argv": ["./renew domain.sh", "--check"],
        }

    def tearDown(self):
        self.input.close()
        os.close(self.write_fd)

    def _answer(self, text):
        os.write(self.write_fd, text.encode("utf-8"))

    def _answer_when_reading(self):
        real_select = select.select
        responded_prompt_count = 0

        def select_with_queued_answer(readers, writers, errors, timeout=None):
            nonlocal responded_prompt_count
            if (
                timeout is not None
                and timeout > 0
                and responded_prompt_count < self.output.answer_prompt_count
                and self.output.responses
            ):
                self._answer(self.output.responses.pop(0))
                responded_prompt_count += 1
            return real_select(readers, writers, errors, timeout)

        return patch(
            "passbro.prompt.select.select", side_effect=select_with_queued_answer
        )

    def test_choices_map_to_decisions(self):
        self.output.responses = ["n\n", "1\n", "h\n"]

        with self._answer_when_reading():
            for expected in ("deny", "once", "hour"):
                with self.subTest(expected=expected):
                    self.assertEqual(
                        Prompter(self.input, self.output, timeout=1).ask(self.request),
                        expected,
                    )

    def test_invalid_answer_reprompts_until_valid(self):
        self.output.responses = ["maybe\n1\n"]

        with self._answer_when_reading():
            self.assertEqual(
                Prompter(self.input, self.output, timeout=1).ask(self.request), "once"
            )
        self.assertIn("Enter n, 1 or h", self.output.getvalue())

    def test_timeout_denies_with_message(self):
        started = time.monotonic()

        result = Prompter(self.input, self.output, timeout=0.02).ask(self.request)

        self.assertEqual(result, "deny")
        self.assertLess(time.monotonic() - started, 1)
        self.assertTrue(self.output.getvalue().endswith("timed out - denied\n"))

    def test_late_input_is_flushed_before_next_request(self):
        prompter = Prompter(self.input, self.output, timeout=0.02)

        self.assertEqual(prompter.ask(self.request), "deny")
        self._answer("1\n")
        self.assertEqual(prompter.ask(self.request), "deny")

        output = self.output.getvalue()
        self.assertEqual(output.count("Decision [n/1/h]: "), 2)
        self.assertEqual(output.count("timed out - denied\n"), 2)

    def test_input_available_after_deadline_is_denied(self):
        monotonic_values = iter((10.0, 130.1))

        def monotonic():
            return next(monotonic_values, 130.1)

        def seed_input(fd, queue):
            self._answer("1\n")

        with patch("passbro.prompt.os.isatty", return_value=True), patch(
            "passbro.prompt.termios.tcflush", side_effect=seed_input
        ), patch("passbro.prompt.time.monotonic", side_effect=monotonic):
            result = Prompter(self.input, self.output, timeout=120).ask(self.request)

        self.assertEqual(result, "deny")
        self.assertIn("timed out - denied\n", self.output.getvalue())

    def test_tty_input_is_flushed_after_question_is_written(self):
        self.output.responses = ["n\n"]

        def flush_input(fd, queue):
            self.output.events.append("input_flushed")

        with self._answer_when_reading(), patch(
            "passbro.prompt.os.isatty", return_value=True
        ), patch(
            "passbro.prompt.termios.tcflush", side_effect=flush_input
        ) as tcflush:
            result = Prompter(self.input, self.output, timeout=1).ask(self.request)

        self.assertEqual(result, "deny")
        tcflush.assert_called_once_with(self.read_fd, termios.TCIFLUSH)
        self.assertLess(
            self.output.events.index("question_written"),
            self.output.events.index("input_flushed"),
        )
        self.assertLess(
            self.output.events.index("output_flushed"),
            self.output.events.index("input_flushed"),
        )

    def test_overlong_answer_is_discarded_and_reprompted(self):
        self.output.responses = ["é" * 33 + "\n1\n"]

        with self._answer_when_reading():
            result = Prompter(self.input, self.output, timeout=1).ask(self.request)

        self.assertEqual(result, "once")
        self.assertIn("Enter n, 1 or h", self.output.getvalue())

    def test_prompt_displays_request_context_and_shell_quoted_argv(self):
        self.output.responses = ["n\n"]

        with self._answer_when_reading():
            Prompter(self.input, self.output, timeout=1).ask(self.request)

        prompt = self.output.getvalue()
        self.assertRegex(prompt, r"Secret request #1 +\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        self.assertIn("Client PID  4321", prompt)
        self.assertIn("Parent      python3 'agent script.py'", prompt)
        self.assertIn("Directory   /tmp/work", prompt)
        self.assertIn("Executable  /usr/bin/renew", prompt)
        self.assertIn("Reason      renew the domain", prompt)
        self.assertIn("PORKBUN_KEY = porkbun/api-key/password", prompt)
        self.assertIn("Command     './renew domain.sh' --check", prompt)

    def test_prompt_displays_executable_write_warning(self):
        self.output.responses = ["n\n"]
        request = dict(
            self.request,
            warning="The file or its directory is writable by the agent - "
            "an h grant does not protect against replacement.",
        )

        with self._answer_when_reading():
            Prompter(self.input, self.output, timeout=1).ask(request)

        self.assertIn(
            "\u26a0 Warning: The file or its directory is writable by the agent",
            self.output.getvalue(),
        )

    def test_terminal_control_characters_are_escaped(self):
        self.output.responses = ["n\n"]
        request = dict(self.request, why="approve\x1b[31m\nforged")

        with self._answer_when_reading():
            Prompter(self.input, self.output, timeout=1).ask(request)

        prompt = self.output.getvalue()
        self.assertIn(r"approve\x1b[31m\x0aforged", prompt)
        self.assertNotIn("\x1b", prompt)

    def test_terminal_unsafe_unicode_in_argv_is_escaped(self):
        self.output.responses = ["n\n"]
        request = dict(
            self.request,
            argv=["run\u202e\u200b\u2028\u2029\ue000\u0378"],
        )

        with self._answer_when_reading():
            Prompter(self.input, self.output, timeout=1).ask(request)

        prompt = self.output.getvalue()
        self.assertIn(r"run\u202e\u200b\u2028\u2029\ue000\u0378", prompt)
        for char in ("\u202e", "\u200b", "\u2028", "\u2029", "\ue000", "\u0378"):
            self.assertNotIn(char, prompt)

    def test_concurrent_requests_are_serialized_in_prompt_order(self):
        self.output.responses = ["1\n", "h\n"]
        prompter = Prompter(self.input, self.output, timeout=1)
        results = []
        first = threading.Thread(target=lambda: results.append(prompter.ask(self.request)))
        second_request = dict(self.request, pid=9876)
        second = threading.Thread(
            target=lambda: results.append(prompter.ask(second_request))
        )

        with self._answer_when_reading():
            first.start()
            second.start()
            first.join(timeout=2)
            second.join(timeout=2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertCountEqual(results, ["once", "hour"])
        prompt = self.output.getvalue()
        self.assertEqual(prompt.count("Decision [n/1/h]: "), 2)
        self.assertEqual(prompt.count("Client PID"), 2)
        first_decision = prompt.index("Decision [n/1/h]: ")
        second_header = prompt.index("Secret request #2", first_decision + 1)
        self.assertGreater(second_header, first_decision)

    def test_outcome_line_is_written_after_each_decision(self):
        for answer, text in (
            ("n\n", "\u2717 denied"),
            ("1\n", "\u2713 allowed once"),
            ("h\n", "\u2713 allowed for 1 hour"),
        ):
            with self.subTest(answer=answer):
                self.output.responses = [answer]
                with self._answer_when_reading():
                    Prompter(self.input, self.output, timeout=1).ask(self.request)
                self.assertTrue(self.output.getvalue().endswith(f"  {text}\n"))

    def test_requests_are_numbered(self):
        self.output.responses = ["n\n", "n\n"]
        prompter = Prompter(self.input, self.output, timeout=1)

        with self._answer_when_reading():
            prompter.ask(self.request)
            prompter.ask(self.request)

        prompt = self.output.getvalue()
        self.assertLess(prompt.index("Secret request #1"), prompt.index("Secret request #2"))

    def test_color_is_used_only_for_terminals_without_no_color(self):
        master, slave = os.openpty()
        try:
            with open(slave, "w", closefd=False) as tty:
                with patch.dict(os.environ, {"TERM": "xterm"}, clear=False):
                    os.environ.pop("NO_COLOR", None)
                    self.assertTrue(Prompter._use_color(tty))
                with patch.dict(os.environ, {"NO_COLOR": "1"}):
                    self.assertFalse(Prompter._use_color(tty))
                with patch.dict(os.environ, {"TERM": "dumb"}):
                    os.environ.pop("NO_COLOR", None)
                    self.assertFalse(Prompter._use_color(tty))
        finally:
            os.close(master)
            os.close(slave)
        self.assertFalse(Prompter._use_color(self.output))

    def test_colored_prompt_still_escapes_untrusted_text(self):
        self.output.responses = ["n\n"]
        prompter = Prompter(self.input, self.output, timeout=1)
        prompter._color = True
        request = dict(self.request, why="approve\x1b[31m")

        with self._answer_when_reading():
            prompter.ask(request)

        prompt = self.output.getvalue()
        self.assertIn(r"Reason     " + "\x1b[0m " + r"approve\x1b[31m" + "\n", prompt)
        self.assertIn("\x1b[31m\u2717\x1b[0m denied", prompt)
        self.assertNotIn("\x1b[1", prompt)

    def test_granted_run_is_shown_as_one_line(self):
        request = dict(self.request, argv=["run\x1b[31m"])
        Prompter(self.input, self.output, timeout=1).notify_granted(request)

        output = self.output.getvalue()
        self.assertRegex(
            output,
            r"^  \d{2}:\d{2}:\d{2} auto-approved \(1h grant\) "
            r"\[PORKBUN_KEY\]: 'run\\x1b\[31m'\n$",
        )
        self.assertNotIn("Decision", output)

    def test_idle_closes_block_without_indent(self):
        Prompter(self.input, self.output, timeout=1).idle()

        self.assertRegex(
            self.output.getvalue(),
            r"^\u2500+\n\u2022 Waiting for requests\. Type \? for commands",
        )

    def test_long_parent_is_cut_to_one_line(self):
        self.output.responses = ["n\n"]
        request = dict(self.request, parent_cmdline="bash -c " + "x" * 300)
        prompter = Prompter(self.input, self.output, timeout=1)

        with self._answer_when_reading():
            prompter.ask(request)

        line = next(
            line for line in self.output.getvalue().splitlines() if "Parent" in line
        )
        self.assertLessEqual(len(line), 72)
        self.assertTrue(line.endswith("\u2026"))

    def test_long_value_wraps_under_value_column(self):
        self.output.responses = ["n\n"]
        request = dict(self.request, why="w" * 100)
        prompter = Prompter(self.input, self.output, timeout=1)

        with self._answer_when_reading():
            prompter.ask(request)

        lines = self.output.getvalue().splitlines()
        start = next(i for i, line in enumerate(lines) if "Reason" in line)
        self.assertTrue(lines[start + 1].startswith(" " * 14 + "w"))
        self.assertTrue(all(len(line) <= 72 for line in lines))

    def test_status_is_one_escaped_line(self):
        Prompter(self.input, self.output, timeout=1).status(
            "\u2713", "done\x1b[31m", "1;32"
        )

        self.assertEqual(self.output.getvalue(), "  \u2713 done\\x1b[31m\n")


if __name__ == "__main__":
    unittest.main()
