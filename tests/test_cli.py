import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from passbro import broker, cli, client
from passbro.vault import Vault
from tests.make_fake_db import make


_BROKER_ERRORS = (
    "denied",
    "timeout",
    "no_such_field",
    "executable_not_found",
    "executable_changed",
    "bad_request",
    "internal_error",
)


class _Prompter:
    def __init__(self, decision):
        self.decision = decision

    def idle(self):

        self.statuses = getattr(self, "statuses", []) + ["<idle>"]


    def status(self, symbol, text, code):

        self.statuses = getattr(self, "statuses", []) + [text]


    def notify_granted(self, request):
        self.notified = getattr(self, "notified", []) + [request]

    def ask(self, request):
        return self.decision


class _Audit:
    def write(self, **record):
        pass


class _BrokenPipeBuffer:
    def write(self, _data):
        raise BrokenPipeError

    def flush(self):
        raise BrokenPipeError


class _BrokenPipeStream:
    buffer = _BrokenPipeBuffer()

    def fileno(self):
        raise OSError("no file descriptor")


@contextmanager
def _running_broker(directory, service):
    path = Path(directory) / "agent.sock"
    server = broker.create_server(path, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield path
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


class CliTests(unittest.TestCase):
    def test_run_preserves_command_arguments_and_forwards_output(self):
        response = {
            "ok": True,
            "exit": 23,
            "stdout_b64": base64.b64encode(b"command output\n").decode("ascii"),
            "stderr_b64": base64.b64encode(b"command warning\n").decode("ascii"),
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        command = ["/tmp/tool with spaces", "--why", "two words", "--", "x"]
        with patch("passbro.cli.client.run", return_value=response) as run:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = cli.main(
                    [
                        "run",
                        "--why",
                        "show status",
                        "-e",
                        "TOKEN=service/token/password",
                        "--timeout",
                        "3",
                        "--",
                        *command,
                    ]
                )

        self.assertEqual(result, 23)
        self.assertEqual(run.call_args.args[:3], (
            "show status",
            {"TOKEN": "service/token/password"},
            command,
        ))
        self.assertEqual(run.call_args.kwargs, {"timeout": 3})
        self.assertEqual(stdout.getvalue(), "command output\n")
        self.assertEqual(stderr.getvalue(), "command warning\n")

    def test_run_converts_signal_exit_status_to_shell_status(self):
        response = {
            "ok": True,
            "exit": -9,
            "stdout_b64": "",
            "stderr_b64": "",
            "truncated": False,
        }
        with patch("passbro.cli.client.run", return_value=response):
            result = cli.main(
                ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
            )
        self.assertEqual(result, 137)

    def test_run_warns_after_output_when_truncated(self):
        for truncated in (False, True):
            with self.subTest(truncated=truncated):
                response = {
                    "ok": True,
                    "exit": 0,
                    "stdout_b64": base64.b64encode(b"command output\n").decode("ascii"),
                    "stderr_b64": base64.b64encode(b"command warning\n").decode("ascii"),
                    "truncated": truncated,
                }
                stdout = io.StringIO()
                stderr = io.StringIO()
                with patch("passbro.cli.client.run", return_value=response):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        result = cli.main(
                            ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                        )

                self.assertEqual(result, 0)
                self.assertEqual(stdout.getvalue(), "command output\n")
                expected_stderr = "command warning\n"
                if truncated:
                    expected_stderr += "passbro: output truncated\n"
                self.assertEqual(stderr.getvalue(), expected_stderr)

    def test_run_broken_stdout_preserves_stderr_and_returns_one(self):
        response = {
            "ok": True,
            "exit": 0,
            "stdout_b64": base64.b64encode(b"cannot write this\n").decode("ascii"),
            "stderr_b64": base64.b64encode(b"stderr preserved\n").decode("ascii"),
            "truncated": False,
        }
        stderr = io.StringIO()
        with patch("passbro.cli.client.run", return_value=response):
            with redirect_stdout(_BrokenPipeStream()), redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )

        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "stderr preserved\n")
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_client_error_returns_one_for_run_and_ls(self):
        with patch("passbro.cli.client.run", side_effect=client.ClientError):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )
        self.assertEqual(result, 1)
        self.assertIn("communication error", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

        with patch("passbro.cli.client.ls", side_effect=client.ClientError):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = cli.main(["ls"])
        self.assertEqual(result, 1)
        self.assertIn("communication error", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_run_getcwd_error_is_reported_without_traceback(self):
        stderr = io.StringIO()
        with patch("passbro.client.os.getcwd", side_effect=FileNotFoundError):
            with redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )

        self.assertEqual(result, 2)
        self.assertIn("cannot determine current directory", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_run_keyboard_interrupt_returns_130_without_traceback(self):
        stderr = io.StringIO()
        with patch("passbro.cli.client.run", side_effect=KeyboardInterrupt):
            with redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )

        self.assertEqual(result, 130)
        self.assertIn("wait interrupted", stderr.getvalue())
        self.assertIn("the command may still run", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_run_help_without_separator_returns_zero(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = cli.main(["run", "-h"])

        self.assertEqual(result, 0)
        self.assertIn("usage: passbro run", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_run_reports_each_protocol_error_and_returns_one(self):
        for code in _BROKER_ERRORS:
            with self.subTest(code=code):
                stdout = io.StringIO()
                stderr = io.StringIO()
                response = {
                    "ok": False,
                    "error": code,
                    "message": f"safe response for {code}",
                }
                with patch("passbro.cli.client.run", return_value=response):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        result = cli.main(
                            ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                        )
                self.assertEqual(result, 1)
                self.assertIn(f"safe response for {code}", stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")

    def test_run_handles_malformed_error_code_without_crashing(self):
        stderr = io.StringIO()
        response = {"ok": False, "error": ["denied"], "message": None}
        with patch("passbro.cli.client.run", return_value=response):
            with redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )
        self.assertEqual(result, 1)
        self.assertIn("passbro agent returned an error", stderr.getvalue())

    def test_missing_agent_returns_two_with_message(self):
        stderr = io.StringIO()
        with patch(
            "passbro.cli.client.run", side_effect=client.AgentUnavailable
        ):
            with redirect_stderr(stderr):
                result = cli.main(
                    ["run", "--why", "test", "-e", "TOKEN=service/token/password", "--", "/bin/true"]
                )
        self.assertEqual(result, 2)
        self.assertIn("passbro agent is not running", stderr.getvalue())

    def test_ls_prints_field_addresses_without_values(self):
        response = {
            "ok": True,
            "entries": [
                {"path": "service/token", "fields": ["username", "password"]}
            ],
        }
        stdout = io.StringIO()
        with patch("passbro.cli.client.ls", return_value=response):
            with redirect_stdout(stdout):
                result = cli.main(["ls"])
        self.assertEqual(result, 0)
        self.assertEqual(
            stdout.getvalue(),
            "service/token/username\nservice/token/password\n",
        )

    def test_run_end_to_end_with_fake_database_and_stub_approval(self):
        password = "fake-test-database-password"
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "fake.kdbx"
            make(database_path, password)
            vault = Vault.open(database_path, password)
            service = broker.Broker(
                vault,
                prompter=_Prompter("once"),
                audit=_Audit(),
            )
            with _running_broker(directory, service) as socket_path:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with patch.dict(os.environ, {"PASSBRO_SOCK": os.fspath(socket_path)}):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        result = cli.main(
                            [
                                "run",
                                "--why",
                                "print fake database token",
                                "-e",
                                "TOKEN=porkbun/api-key/password",
                                "--timeout",
                                "5",
                                "--",
                                sys.executable,
                                "-c",
                                "import os; print(os.environ['TOKEN']); print('command stderr', file=__import__('sys').stderr)",
                            ]
                        )

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "[hidden]\n")
        self.assertEqual(stderr.getvalue(), "command stderr\n")
        self.assertNotIn("FAKE-porkbun-key-123456", stdout.getvalue())

    def test_run_end_to_end_converts_sigkill_to_137(self):
        password = "fake-test-database-password"
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "fake.kdbx"
            make(database_path, password)
            vault = Vault.open(database_path, password)
            service = broker.Broker(
                vault,
                prompter=_Prompter("once"),
                audit=_Audit(),
            )
            with _running_broker(directory, service) as socket_path:
                environment = dict(os.environ)
                environment["PASSBRO_SOCK"] = os.fspath(socket_path)
                environment["PASSBRO_LOG"] = os.fspath(Path(directory) / "log.jsonl")
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "passbro",
                        "run",
                        "--why",
                        "test signal status",
                        "-e",
                        "TOKEN=porkbun/api-key/password",
                        "--timeout",
                        "5",
                        "--",
                        "sh",
                        "-c",
                        "kill -9 $$",
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

        self.assertEqual(result.returncode, 137)


if __name__ == "__main__":
    unittest.main()
