from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import call, Mock, patch

from passbro import broker, client
from passbro.prompt import Prompter


@contextmanager
def _response_server(directory, response):
    path = Path(directory) / "agent.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(path))
    listener.listen(1)
    received = {}

    def serve_once():
        connection, _address = listener.accept()
        with connection:
            payload = bytearray()
            while b"\n" not in payload:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                payload.extend(chunk)
            received["payload"] = json.loads(bytes(payload).split(b"\n", 1)[0])
            connection.sendall(json.dumps(response).encode("utf-8") + b"\n")

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    try:
        yield path, received
    finally:
        listener.close()
        thread.join(timeout=2)


@contextmanager
def _raw_response_server(directory, response_bytes):
    path = Path(directory) / "agent.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(path))
    listener.listen(1)

    def serve_once():
        connection, _address = listener.accept()
        with connection:
            payload = bytearray()
            while b"\n" not in payload:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                payload.extend(chunk)
            if response_bytes:
                try:
                    connection.sendall(response_bytes)
                except OSError:
                    pass

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    try:
        yield path
    finally:
        listener.close()
        thread.join(timeout=2)


class _FakeVault:
    def resolve(self, reference):
        return "fake-secret-value"


class _Audit:
    def write(self, **record):
        pass


class _QueuedPrompter(Prompter):
    def __init__(self, input, output):
        super().__init__(input=input, output=output, timeout=1)
        self._timeout_lock = threading.Lock()

    def idle(self):

        self.statuses = getattr(self, "statuses", []) + ["<idle>"]


    def status(self, symbol, text, code):

        self.statuses = getattr(self, "statuses", []) + [text]


    def notify_granted(self, request):
        self.notified = getattr(self, "notified", []) + [request]

    def ask(self, request):
        with self._timeout_lock:
            self.timeout = 0.25 if request["why"] == "first" else 1
            return super().ask(request)


class ClientTests(unittest.TestCase):
    def test_run_sends_client_context_and_keeps_argv(self):
        response = {"ok": True, "exit": 0}
        with tempfile.TemporaryDirectory() as directory:
            with _response_server(directory, response) as (path, received):
                result = client.run(
                    "rotate token",
                    {"SERVICE_TOKEN": "service/token/password"},
                    ["/bin/echo", "--why", "value with spaces"],
                    timeout=17,
                    socket_path=path,
                )

        self.assertEqual(result, response)
        self.assertEqual(
            received["payload"]["argv"],
            ["/bin/echo", "--why", "value with spaces"],
        )
        self.assertEqual(received["payload"]["cwd"], os.getcwd())
        self.assertTrue(os.path.isabs(received["payload"]["cwd"]))
        self.assertEqual(received["payload"]["client_env"], dict(os.environ))
        self.assertEqual(received["payload"]["timeout"], 17)
        self.assertEqual(
            received["payload"]["env"],
            {"SERVICE_TOKEN": "service/token/password"},
        )
        self.assertEqual(client._response_timeout(received["payload"]), 147)

    def test_ls_sends_only_ls_operation(self):
        response = {"ok": True, "entries": []}
        with tempfile.TemporaryDirectory() as directory:
            with _response_server(directory, response) as (path, received):
                result = client.ls(socket_path=path)

        self.assertEqual(result, response)
        self.assertEqual(received["payload"], {"op": "ls"})
        self.assertEqual(client._response_timeout(received["payload"]), 10)

    def test_missing_socket_raises_agent_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sock"
            with self.assertRaises(client.AgentUnavailable):
                client.request({"op": "ls"}, socket_path=path)

    def test_request_rejects_incomplete_and_malformed_responses(self):
        invalid_responses = (
            ("eof", b""),
            ("invalid json", b"{\n"),
            ("invalid utf8", b"\xff\n"),
            ("ok is not bool", b'{"ok":1}\n'),
            ("oversized", b"x" * (client._MAX_RESPONSE_BYTES + 1)),
        )
        for name, response_bytes in invalid_responses:
            with self.subTest(response=name):
                with tempfile.TemporaryDirectory() as directory:
                    with _raw_response_server(directory, response_bytes) as path:
                        with self.assertRaises(client.ClientError):
                            client.request({"op": "ls"}, socket_path=path)

    def test_request_rejects_data_after_response_newline(self):
        connection = Mock()
        connection.recv.return_value = b'{"ok":true}\nextra'
        with patch("passbro.client.socket.socket", return_value=connection):
            with self.assertRaises(client.ClientError):
                client.request({"op": "ls"}, socket_path="/tmp/agent.sock")

    def test_socket_timeout_is_client_error_and_read_timeout_is_cleared(self):
        connection = Mock()
        connection.recv.side_effect = socket.timeout
        with patch("passbro.client.socket.socket", return_value=connection):
            with self.assertRaises(client.ClientError):
                client.request({"op": "ls"}, socket_path="/tmp/agent.sock")

        self.assertEqual(connection.settimeout.call_args_list, [call(10), call(None)])

    def test_queued_request_waits_for_its_owner_decision_after_first_times_out(self):
        read_fd, write_fd = os.pipe()
        owner_input = os.fdopen(read_fd, "rb", buffering=0)
        output = io.StringIO()
        prompter = _QueuedPrompter(owner_input, output)
        service = broker.Broker(_FakeVault(), prompter=prompter, audit=_Audit())
        results = {}
        failures = {}

        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "agent.sock"
            server = broker.create_server(socket_path, service)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

            def send_request(name):
                try:
                    results[name] = client.run(
                        name,
                        {"TOKEN": "service/token/password"},
                        [sys.executable, "-c", "pass"],
                        timeout=0.1,
                        socket_path=socket_path,
                    )
                except Exception as error:
                    failures[name] = error

            try:
                with patch.object(client, "_PROMPT_TIMEOUT_SECONDS", 0.25), patch.object(
                    client, "_RESPONSE_RESERVE_SECONDS", 0.1
                ):
                    first = threading.Thread(target=send_request, args=("first",))
                    first.start()
                    first_deadline = time.monotonic() + 2
                    while (
                        output.getvalue().count("Secret request") < 1
                        and time.monotonic() < first_deadline
                    ):
                        time.sleep(0.01)
                    self.assertGreaterEqual(
                        output.getvalue().count("Secret request"), 1
                    )

                    second = threading.Thread(target=send_request, args=("second",))
                    second.start()
                    second_deadline = time.monotonic() + 2
                    while (
                        output.getvalue().count("Secret request") < 2
                        and time.monotonic() < second_deadline
                    ):
                        time.sleep(0.01)
                    self.assertGreaterEqual(
                        output.getvalue().count("Secret request"), 2
                    )
                    time.sleep(0.3)
                    os.write(write_fd, b"1\n")

                    first.join(timeout=3)
                    second.join(timeout=3)
            finally:
                server.shutdown()
                server_thread.join(timeout=2)
                server.server_close()
                owner_input.close()
                os.close(write_fd)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, {})
        self.assertFalse(results["first"]["ok"])
        self.assertTrue(results["second"]["ok"])

    def test_socket_creation_failure_raises_agent_unavailable(self):
        with patch("passbro.client.socket.socket", side_effect=OSError):
            with self.assertRaises(client.AgentUnavailable):
                client.request({"op": "ls"}, socket_path="/tmp/agent.sock")

    def test_run_timeout_must_fit_broker_range(self):
        for timeout in (float("nan"), 601):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    client._response_timeout({"op": "run", "timeout": timeout})

    def test_default_socket_path_uses_override_then_runtime_directory(self):
        self.assertEqual(
            client.default_socket_path(
                {"PASSBRO_SOCK": "/tmp/custom.sock", "XDG_RUNTIME_DIR": "/run/user/1"}
            ),
            Path("/tmp/custom.sock"),
        )
        self.assertEqual(
            client.default_socket_path({"XDG_RUNTIME_DIR": "/run/user/1"}),
            Path("/run/user/1/passbro/agent.sock"),
        )
        with self.assertRaises(RuntimeError):
            client.default_socket_path({})


if __name__ == "__main__":
    unittest.main()
