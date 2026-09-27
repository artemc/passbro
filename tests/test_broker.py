import base64
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from passbro import broker, cli
from passbro.runner import Result
from passbro.vault import NoSuchField
from tests import make_fake_db


class _Vault:
    def __init__(self, values=None):
        self.values = values or {"service/token/password": "secret-value"}
        self.resolve_calls = []

    def list(self):
        return [{"path": "service/token", "fields": ["password"]}]

    def resolve(self, reference):
        self.resolve_calls.append(reference)
        try:
            return self.values[reference]
        except KeyError:
            raise NoSuchField("field not available")


class _Prompter:
    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.requests = []

    def idle(self):

        self.statuses = getattr(self, "statuses", []) + ["<idle>"]


    def status(self, symbol, text, code):

        self.statuses = getattr(self, "statuses", []) + [text]


    def notify_granted(self, request):
        self.notified = getattr(self, "notified", []) + [request]

    def ask(self, request):
        self.requests.append(request)
        return self.decisions.pop(0)


class _Audit:
    def __init__(self):
        self.records = []
        self.lock = threading.Lock()

    def write(self, **record):
        with self.lock:
            self.records.append(record)


class _Runner:
    def __init__(
        self,
        stdout=b"got secret-value",
        stderr=b"",
        exit_code=0,
        truncated=False,
        timed_out=False,
    ):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.truncated = truncated
        self.timed_out = timed_out
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return Result(
            exit=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            truncated=self.truncated,
            timed_out=self.timed_out,
        )


@contextmanager
def _running_server(directory, test_broker):
    path = Path(directory) / "agent.sock"
    server = broker.create_server(path, test_broker)
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


def _request(path, request):
    return _request_raw(path, json.dumps(request).encode("utf-8") + b"\n")


def _request_raw(path, payload):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    try:
        connection.connect(os.fspath(path))
        connection.sendall(payload)
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        connection.close()
    return json.loads(b"".join(chunks).decode("utf-8"))


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "op": "run",
            "why": "rotate service token",
            "env": {"SERVICE_TOKEN": "service/token/password"},
            "argv": ["/bin/echo", "ready"],
            "cwd": "/tmp",
            "client_env": {"PATH": "/usr/bin", "SERVICE_TOKEN": "client-value"},
        }

    def _make_broker(self, decisions=(), values=None, runner=None):
        self.vault = _Vault(values)
        self.prompter = _Prompter(decisions)
        self.audit = _Audit()
        self.runner = runner or _Runner()
        return broker.Broker(
            self.vault,
            prompter=self.prompter,
            audit=self.audit,
            runner=self.runner,
        )

    def test_run_defaults_and_timeout_range(self):
        request = dict(self.request)
        request.pop("cwd")
        request.pop("client_env")
        values = broker._validate_run_request(request)

        self.assertIsNone(values["cwd"])
        self.assertEqual(values["client_env"], {})
        self.assertEqual(values["timeout"], 600)
        self.assertEqual(broker.MAX_TIMEOUT, 600)
        self.assertIsNone(
            broker._validate_run_request(dict(request, timeout=600.1))
        )

    def test_ls_returns_entry_metadata(self):
        service = self._make_broker()
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, {"op": "ls"})

        self.assertEqual(
            response,
            {
                "ok": True,
                "entries": [{"path": "service/token", "fields": ["password"]}],
            },
        )
        self.assertEqual(self.prompter.requests, [])

    def test_deny_does_not_run_command(self):
        service = self._make_broker(["deny"])
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        self.assertEqual(response["error"], "denied")
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(len(self.prompter.requests), 1)
        self.assertEqual(self.audit.records[0]["decision"], "deny")
        self.assertIsNone(self.audit.records[0]["exit"])

    def _statuses(self, decisions, runner=None):
        service = self._make_broker(decisions, runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                _request(path, self.request)
        return getattr(self.prompter, "statuses", [])

    def test_status_after_approval_reports_run_delivery_and_idle(self):
        self.assertEqual(
            self._statuses(["once"]),
            [
                "Running the command...",
                "Command finished: exit code 0",
                "Response delivered to the agent",
                "<idle>",
            ],
        )

    def test_status_reports_nonzero_exit_and_timeout(self):
        self.assertIn(
            "Command finished: exit code 3",
            self._statuses(["once"], runner=_Runner(exit_code=3)),
        )
        self.assertIn(
            "Command timed out after 600s and was stopped",
            self._statuses(["once"], runner=_Runner(timed_out=True)),
        )

    def test_status_after_deny_reports_delivery_and_idle(self):
        self.assertEqual(
            self._statuses(["deny"]),
            ["Response delivered to the agent", "<idle>"],
        )

    def test_no_status_for_ls(self):
        service = self._make_broker()
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                _request(path, {"op": "ls"})
        self.assertEqual(getattr(self.prompter, "statuses", []), [])

    def test_once_runs_with_secret_over_client_environment_and_masks_output(self):
        service = self._make_broker(["once"])
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        self.assertTrue(response["ok"])
        self.assertEqual(response["decision"], "once")
        self.assertEqual(response["exit"], 0)
        self.assertEqual(
            base64.b64decode(response["stdout_b64"]),
            "got [hidden]".encode("utf-8"),
        )
        self.assertEqual(len(self.runner.calls), 1)
        resolved_exe = os.path.realpath(self.request["argv"][0])
        self.assertEqual(self.runner.calls[0][0], tuple(self.request["argv"]))
        self.assertEqual(self.runner.calls[0][1]["executable"], resolved_exe)
        self.assertEqual(
            self.runner.calls[0][1]["env"],
            {"PATH": "/usr/bin", "SERVICE_TOKEN": "secret-value"},
        )
        self.assertEqual(
            self.runner.calls[0][1]["cwd"], os.path.realpath("/tmp")
        )
        self.assertEqual(
            self.runner.calls[0][1]["limit"],
            1024 * 1024 + len(b"secret-value"),
        )
        self.assertEqual(self.audit.records[0]["env"], self.request["env"])
        self.assertEqual(self.audit.records[0]["exe"], resolved_exe)
        self.assertEqual(
            self.audit.records[0]["cwd"], os.path.realpath(self.request["cwd"])
        )
        self.assertEqual(self.prompter.requests[0]["exe"], resolved_exe)
        self.assertEqual(self.audit.records[0]["decision"], "once")
        self.assertIsNone(self.audit.records[0]["exit"])
        self.assertEqual(self.audit.records[1]["exit"], 0)
        self.assertFalse(self.audit.records[1]["timed_out"])
        self.assertNotIn("client-value", json.dumps(self.audit.records))
        self.assertNotIn("secret-value", json.dumps(self.audit.records))

    def test_decision_is_audited_before_runner_starts(self):
        service = self._make_broker(["once"])

        class ObservingRunner:
            def __init__(self, audit):
                self.audit = audit
                self.records_at_start = None

            def __call__(self, argv, **kwargs):
                self.records_at_start = list(self.audit.records)
                return Result(0, b"", b"", False, False)

        runner = ObservingRunner(self.audit)
        service.runner = runner
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                _request(path, self.request)

        self.assertEqual(len(runner.records_at_start), 1)
        self.assertEqual(runner.records_at_start[0]["decision"], "once")
        self.assertIsNone(runner.records_at_start[0]["exit"])
        self.assertEqual(len(self.audit.records), 2)
        self.assertEqual(self.audit.records[1]["exit"], 0)
        self.assertIn("timed_out", self.audit.records[1])

    def test_hour_grant_skips_prompt_on_matching_second_request(self):
        service = self._make_broker(["hour"])
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                first = _request(path, self.request)
                second = _request(path, self.request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "hour")
        self.assertEqual(len(self.prompter.requests), 1)
        self.assertEqual(len(self.prompter.notified), 1)
        self.assertEqual(self.prompter.notified[0]["argv"], self.request["argv"])
        self.assertEqual(len(self.runner.calls), 2)
        run_records = [
            record for record in self.audit.records if "decision" in record
        ]
        self.assertFalse(run_records[0]["granted"])
        self.assertTrue(run_records[2]["granted"])

    def test_different_argv_does_not_reuse_hour_grant(self):
        service = self._make_broker(["hour", "once"])
        request = dict(self.request)
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                first = _request(path, request)
                request["argv"] = ["/bin/echo", "different"]
                second = _request(path, request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "once")
        self.assertEqual(len(self.prompter.requests), 2)

    def test_different_cwd_does_not_reuse_hour_grant(self):
        service = self._make_broker(["hour", "once"])
        request = dict(self.request)
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                first = _request(path, request)
                request["cwd"] = "/var/tmp"
                second = _request(path, request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "once")
        self.assertEqual(len(self.prompter.requests), 2)

    def test_different_path_resolution_does_not_reuse_hour_grant(self):
        service = self._make_broker(["hour", "once"])
        request = dict(self.request)
        request["argv"] = ["passbro-command", "--check"]

        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "first"
            second_path = Path(directory) / "second"
            first_path.mkdir()
            second_path.mkdir()
            for executable in (first_path / "passbro-command", second_path / "passbro-command"):
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)
            request["client_env"] = {"PATH": os.fspath(first_path)}

            with _running_server(directory, service) as path:
                first = _request(path, request)
                request["client_env"] = {"PATH": os.fspath(second_path)}
                second = _request(path, request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "once")
        self.assertEqual(len(self.prompter.requests), 2)
        self.assertEqual(
            self.prompter.requests[0]["exe"],
            os.path.realpath(first_path / "passbro-command"),
        )
        self.assertEqual(
            self.prompter.requests[1]["exe"],
            os.path.realpath(second_path / "passbro-command"),
        )

    def test_relative_executable_path_is_resolved_from_request_cwd(self):
        service = self._make_broker(["once"])
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory) / "work"
            binary_directory = cwd / "bin"
            binary_directory.mkdir(parents=True)
            executable = binary_directory / "passbro-command"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            request = dict(
                self.request,
                argv=["./bin/passbro-command", "--check"],
                cwd=os.fspath(cwd),
            )

            with _running_server(directory, service) as path:
                response = _request(path, request)

        resolved_exe = os.path.realpath(executable)
        self.assertEqual(response["decision"], "once")
        self.assertEqual(self.runner.calls[0][0], tuple(request["argv"]))
        self.assertEqual(self.runner.calls[0][1]["executable"], resolved_exe)
        self.assertEqual(self.prompter.requests[0]["exe"], resolved_exe)

    def test_relative_cwd_is_rejected_without_resolving_fields(self):
        service = self._make_broker(["once"])
        request = dict(self.request, cwd="relative/work")

        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(self.prompter.requests, [])
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "bad_request"}],
        )

    def test_missing_cwd_uses_normalized_broker_working_directory_everywhere(self):
        service = self._make_broker(["once"])
        request = dict(self.request)
        request.pop("cwd")
        expected_cwd = os.path.realpath(os.getcwd())

        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                _request(path, request)

        self.assertEqual(self.prompter.requests[0]["cwd"], expected_cwd)
        self.assertEqual(self.audit.records[0]["cwd"], expected_cwd)
        self.assertEqual(self.runner.calls[0][1]["cwd"], expected_cwd)

    def test_missing_client_path_uses_os_defpath(self):
        service = self._make_broker(["once"])
        request = dict(self.request, argv=["sh", "-c", "exit 0"], client_env={})

        with tempfile.TemporaryDirectory() as directory:
            request["cwd"] = directory
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["decision"], "once")
        self.assertTrue(os.path.isabs(self.prompter.requests[0]["exe"]))
        self.assertTrue(os.path.isfile(self.prompter.requests[0]["exe"]))
        self.assertEqual(self.runner.calls[0][0], tuple(request["argv"]))

    def test_relative_and_empty_client_path_elements_use_request_cwd(self):
        service = self._make_broker(["once", "once"])
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory) / "work"
            (cwd / "bin").mkdir(parents=True)
            relative_executable = cwd / "bin" / "passbro-command"
            cwd_executable = cwd / "passbro-command"
            for executable in (relative_executable, cwd_executable):
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)

            with _running_server(directory, service) as path:
                relative_request = dict(
                    self.request,
                    argv=["passbro-command"],
                    cwd=os.fspath(cwd),
                    client_env={"PATH": "bin"},
                )
                relative_response = _request(path, relative_request)
                empty_request = dict(
                    relative_request,
                    client_env={"PATH": ""},
                )
                empty_response = _request(path, empty_request)

        self.assertEqual(relative_response["decision"], "once")
        self.assertEqual(empty_response["decision"], "once")
        self.assertEqual(
            [request["exe"] for request in self.prompter.requests],
            [os.path.realpath(relative_executable), os.path.realpath(cwd_executable)],
        )

    def test_canonical_cwd_change_does_not_reuse_hour_grant(self):
        service = self._make_broker(["hour", "once"])
        with tempfile.TemporaryDirectory() as directory:
            first_dir = Path(directory) / "first"
            second_dir = Path(directory) / "second"
            for target in (first_dir, second_dir):
                (target / "bin").mkdir(parents=True)
                executable = target / "bin" / "passbro-command"
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)
            cwd_link = Path(directory) / "work-link"
            cwd_link.symlink_to(first_dir, target_is_directory=True)
            request = dict(
                self.request,
                argv=["./bin/passbro-command"],
                cwd=os.fspath(cwd_link),
            )

            with _running_server(directory, service) as path:
                first = _request(path, request)
                cwd_link.unlink()
                cwd_link.symlink_to(second_dir, target_is_directory=True)
                second = _request(path, request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "once")
        self.assertEqual(len(self.prompter.requests), 2)
        self.assertEqual(self.prompter.requests[0]["cwd"], os.fspath(first_dir))
        self.assertEqual(self.prompter.requests[1]["cwd"], os.fspath(second_dir))

    def test_replacing_executable_invalidates_hour_grant(self):
        service = self._make_broker(["hour", "once"])
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            executable = cwd / "renew.sh"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            request = dict(
                self.request,
                argv=["./renew.sh"],
                cwd=os.fspath(cwd),
            )

            with _running_server(directory, service) as path:
                first = _request(path, request)
                replacement = cwd / "replacement"
                replacement.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                replacement.chmod(0o700)
                replacement.replace(executable)
                second = _request(path, request)

        self.assertEqual(first["decision"], "hour")
        self.assertEqual(second["decision"], "once")
        self.assertEqual(len(self.prompter.requests), 2)

    def test_executable_change_after_prompt_is_rejected_without_running(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            executable = cwd / "renew.sh"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)

            class ReplacingPrompter(_Prompter):
                def ask(inner_self, prompt_request):
                    inner_self.requests.append(prompt_request)
                    replacement = cwd / "replacement"
                    replacement.write_text(
                        "#!/bin/sh\nexit 1\n", encoding="utf-8"
                    )
                    replacement.chmod(0o700)
                    replacement.replace(executable)
                    return "once"

            prompter = ReplacingPrompter([])
            service = self._make_broker(runner=_Runner())
            service.prompter = prompter
            request = dict(
                self.request,
                argv=["./renew.sh"],
                cwd=os.fspath(cwd),
            )

            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "executable_changed")
        self.assertEqual(service.runner.calls, [])
        self.assertEqual(
            self.audit.records[-1],
            {"pid": os.getpid(), "error": "executable_changed"},
        )
        self.assertNotIn("service/token/password", json.dumps(self.audit.records[-1]))

    def test_owner_prompt_warns_when_executable_or_directory_is_writable(self):
        service = self._make_broker(["deny"])
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            executable = cwd / "renew.sh"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            request = dict(
                self.request,
                argv=["./renew.sh"],
                cwd=os.fspath(cwd),
            )

            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "denied")
        self.assertIn("is writable by the agent", self.prompter.requests[0]["warning"])

    def test_argv0_symlink_is_preserved_while_resolved_executable_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "shell-alias"
            alias.symlink_to("/bin/sh")
            resolved_exe = os.path.realpath(alias)
            argv = [os.fspath(alias), "-c", "printf '%s' \"$0\""]
            request = dict(
                self.request,
                argv=argv,
                cwd=directory,
                client_env={},
            )
            runner_calls = []

            def run_command(command_argv, **kwargs):
                runner_calls.append((command_argv, kwargs))
                return broker.runner_module.run(command_argv, **kwargs)

            service = self._make_broker(["once"], runner=run_command)
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(
            base64.b64decode(response["stdout_b64"]), os.fspath(alias).encode()
        )
        self.assertEqual(runner_calls[0][0], tuple(argv))
        self.assertEqual(runner_calls[0][1]["executable"], resolved_exe)

    def test_unresolvable_executable_fails_without_prompt_or_reference(self):
        service = self._make_broker(["once"])
        request = dict(self.request)
        request["argv"] = ["passbro-command-that-does-not-exist"]
        request["client_env"] = {"PATH": "/missing/passbro/path"}

        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "executable_not_found")
        self.assertEqual(self.prompter.requests, [])
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "executable_not_found"}],
        )

    def test_missing_field_fails_before_prompt(self):
        service = self._make_broker(["once"])
        request = dict(self.request)
        request["env"] = {"SERVICE_TOKEN": "service/token/missing"}
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "no_such_field")
        self.assertEqual(self.prompter.requests, [])
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "no_such_field"}],
        )
        self.assertNotIn("service/token/missing", json.dumps(self.audit.records))

    def test_foreign_uid_is_rejected_without_resolving_fields(self):
        service = self._make_broker(["once"])
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                with patch(
                    "passbro.broker._peer_credentials",
                    return_value=(1234, os.getuid() + 1, os.getgid()),
                ):
                    response = _request(path, self.request)

        self.assertEqual(response["error"], "denied")
        self.assertEqual(self.prompter.requests, [])
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.vault.resolve_calls, [])

    def test_short_secret_creates_warning_with_reference_only(self):
        service = self._make_broker(["once"], values={"service/token/password": "abc"})
        runner = _Runner(stdout=b"received abc")
        service.runner = runner
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        self.assertEqual(
            base64.b64decode(response["stdout_b64"]),
            b"received abc",
        )
        warnings = [record for record in self.audit.records if "warning" in record]
        self.assertEqual(
            warnings,
            [{"warning": "short_secret_not_masked", "ref": "service/token/password"}],
        )
        self.assertNotIn("abc", json.dumps(warnings))

    def test_invalid_request_does_not_resolve_any_fields(self):
        service = self._make_broker(["once"])
        request = dict(self.request, timeout=float("inf"))
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "bad_request"}],
        )
        self.assertEqual(self.prompter.requests, [])

    def test_unreasonably_large_integer_timeout_is_bad_request(self):
        service = self._make_broker(["once"])
        request = dict(self.request, timeout=10**1000)
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, request)

        self.assertEqual(response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "bad_request"}],
        )
        self.assertEqual(self.prompter.requests, [])

    def test_deep_json_and_5000_digit_integer_are_bad_request(self):
        service = self._make_broker(["once"])
        deep = (
            b'{"op":"ls","deep":'
            + b"[" * 10000
            + b"0"
            + b"]" * 10000
            + b"}\n"
        )
        huge_integer = b'{"op":"run","timeout":' + b"9" * 5000 + b"}\n"
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                deep_response = _request_raw(path, deep)
                integer_response = _request_raw(path, huge_integer)

        self.assertEqual(deep_response["error"], "bad_request")
        self.assertEqual(integer_response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(len(self.audit.records), 2)
        self.assertTrue(
            all(record["error"] == "bad_request" for record in self.audit.records)
        )

    def test_two_mibibyte_request_gets_json_bad_request(self):
        service = self._make_broker(["once"])
        payload = b'"' + b"x" * (2 * 1024 * 1024) + b'"\n'
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request_raw(path, payload)

        self.assertEqual(response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])
        self.assertEqual(
            self.audit.records,
            [{"pid": os.getpid(), "error": "bad_request"}],
        )

    def test_incomplete_request_times_out_as_bad_request(self):
        service = self._make_broker(["once"])
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                with patch("passbro.broker._REQUEST_TIMEOUT_SECONDS", 0.05):
                    response = _request_raw(path, b'{"op":')

        self.assertEqual(response["error"], "bad_request")
        self.assertEqual(self.vault.resolve_calls, [])

    def test_secret_crossing_output_limit_is_masked_before_truncation(self):
        limit = 1024 * 1024
        secret = "secret-value"
        marker_length = len("[hidden]".encode("utf-8"))
        runner = _Runner(
            stdout=b"x" * (limit - marker_length) + secret.encode() + b"tail"
        )
        service = self._make_broker(["once"], runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        output = base64.b64decode(response["stdout_b64"])
        self.assertEqual(len(output), limit)
        self.assertNotIn(secret.encode(), output)
        self.assertIn("[hidden]".encode(), output)
        self.assertTrue(response["truncated"])

    def test_timed_out_command_returns_error_without_output(self):
        service = self._make_broker(["once"], runner=_Runner(timed_out=True))
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        self.assertEqual(response["error"], "timeout")
        self.assertNotIn("stdout_b64", response)
        self.assertNotIn("stderr_b64", response)
        self.assertTrue(self.audit.records[-1]["timed_out"])

    def test_runner_exception_is_audited(self):
        class RaisingRunner:
            def __call__(self, argv, **kwargs):
                raise RuntimeError("runner failed")

        service = self._make_broker(["once"], runner=RaisingRunner())
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                response = _request(path, self.request)

        self.assertEqual(response["error"], "internal_error")
        self.assertEqual(len(self.audit.records), 2)
        self.assertIsNone(self.audit.records[0]["exit"])
        self.assertIsNone(self.audit.records[1]["exit"])
        self.assertTrue(self.audit.records[1]["runner_error"])

    def test_unavailable_peer_credentials_drains_before_response(self):
        service = self._make_broker(["once"])
        payload = b'"' + b"x" * (2 * 1024 * 1024) + b'"\n'
        with tempfile.TemporaryDirectory() as directory:
            with _running_server(directory, service) as path:
                with patch(
                    "passbro.broker._peer_credentials",
                    side_effect=OSError("unavailable"),
                ):
                    response = _request_raw(path, payload)

        self.assertEqual(response["error"], "denied")
        self.assertEqual(self.vault.resolve_calls, [])

    def test_server_error_hook_writes_one_fixed_line(self):
        service = self._make_broker()
        with tempfile.TemporaryDirectory() as directory:
            server = broker.create_server(Path(directory) / "agent.sock", service)
            try:
                output = io.StringIO()
                with patch("passbro.broker.sys.stderr", output):
                    server.handle_error(None, None)
            finally:
                server.server_close()
                Path(directory, "agent.sock").unlink()

        self.assertEqual(output.getvalue(), "passbro: request handler failed\n")

    def test_socket_directory_and_socket_modes(self):
        service = self._make_broker()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "private"
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            path = parent / "agent.sock"
            server = broker.create_server(path, service)
            try:
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                server.server_close()
                path.unlink()

    def test_existing_live_socket_is_not_removed(self):
        service = self._make_broker()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sock"
            server = broker.create_server(path, service)
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    broker.create_server(path, service)
                self.assertTrue(path.exists())
            finally:
                server.server_close()
                path.unlink()

    def test_stale_socket_is_removed_and_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sock"
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(os.fspath(path))
            stale.close()

            server = broker.create_server(path, self._make_broker())
            try:
                self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
            finally:
                server.server_close()
                path.unlink()

    def test_regular_file_at_socket_path_is_not_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sock"
            path.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "not a socket"):
                broker.create_server(path, self._make_broker())

            self.assertEqual(path.read_text(encoding="utf-8"), "keep")

    def test_serve_removes_socket_when_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sock"
            with patch.object(
                broker.BrokerServer,
                "serve_forever",
                side_effect=KeyboardInterrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    broker.serve(
                        self._make_broker().vault,
                        socket_path=path,
                        prompter=_Prompter([]),
                        audit=_Audit(),
                    )

            self.assertFalse(path.exists())


class AgentCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "fake.kdbx"
        make_fake_db.make(self.db, "fake-password")

    def _main(self, passwords):
        stderr = io.StringIO()
        with (
            patch("passbro.cli.getpass", side_effect=passwords) as password,
            patch("passbro.broker.serve") as serve,
            patch("sys.stderr", stderr),
        ):
            result = cli.main(["agent", "--db", str(self.db)])
        return result, password, serve, stderr.getvalue()

    def test_agent_prompts_for_password_opens_vault_and_serves(self):
        result, password, serve, output = self._main(["fake-password"])

        self.assertEqual(result, 0)
        password.assert_called_once()
        serve.assert_called_once()
        self.assertIn("Unlocking database...", output)
        self.assertIn("Database unlocked: 2 entries", output)

    def test_agent_ready_callback_reports_socket(self):
        stderr = io.StringIO()
        result, _password, serve, _output = self._main(["fake-password"])
        with (
            patch("sys.stderr", stderr),
            patch("passbro.console.Console.start") as start_console,
        ):
            serve.call_args.kwargs["on_ready"]("/run/agent.sock")

        self.assertEqual(result, 0)
        self.assertIn("Listening on /run/agent.sock", stderr.getvalue())
        self.assertIn("Type ? for commands, Ctrl+C to stop", stderr.getvalue())
        start_console.assert_called_once()

    def test_wrong_password_is_reported_and_asked_again(self):
        result, password, serve, output = self._main(["bad", "fake-password"])

        self.assertEqual(result, 0)
        self.assertEqual(password.call_count, 2)
        self.assertIn("Wrong master password (2 attempts left)", output)
        serve.assert_called_once()

    def test_three_wrong_passwords_stop_the_agent(self):
        result, password, serve, output = self._main(["a", "b", "c"])

        self.assertEqual(result, 2)
        self.assertEqual(password.call_count, 3)
        self.assertIn("too many wrong passwords", output)
        serve.assert_not_called()

    def test_missing_database_is_reported_before_password(self):
        self.db = Path(self.directory.name) / "missing.kdbx"
        result, password, serve, output = self._main([])

        self.assertEqual(result, 2)
        password.assert_not_called()
        self.assertIn("database not found", output)


if __name__ == "__main__":
    unittest.main()
