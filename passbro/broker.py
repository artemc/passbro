"""Unix-socket broker for approved KeePass-backed command execution."""

import base64
import errno
import json
import math
import os
from pathlib import Path
import shutil
import socket
import socketserver
import stat
import struct
import sys
import threading

from passbro import audit as audit_module
from passbro import runner as runner_module
from passbro.grants import Grants
from passbro.mask import MIN_SECRET_LENGTH, mask
from passbro.prompt import Prompter
from passbro.term import DIM, GREEN, RED, YELLOW
from passbro.vault import Ambiguous, NoSuchEntry, NoSuchField


_MAX_REQUEST_BYTES = 1024 * 1024
_MAX_OUTPUT_BYTES = 1024 * 1024
_DEFAULT_TIMEOUT = 600
MAX_TIMEOUT = 600
_REQUEST_TIMEOUT_SECONDS = 10.0
_DRAIN_TIMEOUT_SECONDS = 1.0
_DRAIN_CHUNK_BYTES = 64 * 1024
_MAX_DRAIN_BYTES = 4 * _MAX_REQUEST_BYTES
_HOUR_SECONDS = 60 * 60
_Ucred = struct.Struct("3i")


def _error(code, message):
    return {"ok": False, "error": code, "message": message}


def _proc_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as source:
            raw = source.read()
    except OSError:
        return []
    return [
        part.decode("utf-8", errors="replace")
        for part in raw.split(b"\0")
        if part
    ]


def _parent_cmdline(pid):
    """Return the peer process parent's argv, or an empty list if unavailable."""
    try:
        with open(f"/proc/{pid}/stat", "rt", encoding="ascii") as source:
            stat_line = source.read()
        # The command name is parenthesized and may itself contain spaces or ')'.
        fields_after_comm = stat_line.rsplit(")", 1)[1].split()
        parent_pid = int(fields_after_comm[1])
    except (OSError, IndexError, ValueError):
        return []
    if parent_pid <= 0:
        return []
    return _proc_cmdline(parent_pid)


def _peer_credentials(connection):
    if not hasattr(socket, "SO_PEERCRED"):
        raise OSError("peer credentials are unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _Ucred.size)
    return _Ucred.unpack(raw[:_Ucred.size])


def _valid_string(value, *, allow_empty=True):
    return (
        isinstance(value, str)
        and (allow_empty or bool(value))
        and "\0" not in value
    )


def _resolve_executable(argv0, cwd, client_env):
    """Resolve argv[0] once using the request's cwd and client PATH."""
    if "/" in argv0:
        candidate = argv0 if os.path.isabs(argv0) else os.path.join(cwd, argv0)
    else:
        client_path = client_env.get("PATH", os.defpath)
        absolute_path = []
        for element in client_path.split(os.pathsep):
            if os.path.isabs(element):
                absolute_path.append(os.path.abspath(element))
            else:
                absolute_path.append(
                    os.path.abspath(os.path.join(cwd, element or "."))
                )
        candidate = shutil.which(argv0, path=os.pathsep.join(absolute_path))
        if candidate is None:
            return None

    resolved = os.path.realpath(candidate)
    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _normalize_cwd(cwd):
    if cwd is None:
        cwd = os.getcwd()
    if not os.path.isabs(cwd):
        return None
    return os.path.realpath(cwd)


def _executable_identity(executable):
    try:
        info = os.stat(executable)
    except OSError:
        return None
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _validate_run_request(request):
    why = request.get("why")
    env = request.get("env")
    argv = request.get("argv")
    cwd = request.get("cwd")
    client_env = request.get("client_env", {})
    timeout = request.get("timeout", _DEFAULT_TIMEOUT)

    if not _valid_string(why):
        return None
    if not isinstance(env, dict) or not env:
        return None
    if not isinstance(argv, list) or not argv or not all(
        _valid_string(arg) for arg in argv
    ) or not argv[0]:
        return None
    if cwd is not None and not _valid_string(cwd):
        return None
    if not isinstance(client_env, dict):
        return None
    for name, value in client_env.items():
        if (
            not _valid_string(name, allow_empty=False)
            or "=" in name
            or not _valid_string(value)
        ):
            return None
    for name, reference in env.items():
        if (
            not _valid_string(name, allow_empty=False)
            or "=" in name
            or not _valid_string(reference, allow_empty=False)
        ):
            return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return None
    if timeout < 0 or timeout > MAX_TIMEOUT or not math.isfinite(timeout):
        return None

    return {
        "why": why,
        "env": env,
        "argv": argv,
        "cwd": cwd,
        "client_env": client_env,
        "timeout": timeout,
    }


class Broker:
    """Resolve requests, ask the owner, run approved commands, and audit."""

    def __init__(self, vault, prompter=None, grants=None, audit=None, runner=None):
        self.vault = vault
        self.prompter = (
            Prompter(input=sys.stdin, output=sys.stderr)
            if prompter is None
            else prompter
        )
        self.grants = Grants() if grants is None else grants
        self.audit = (
            audit_module.Audit(default_log_path()) if audit is None else audit
        )
        self.runner = runner_module.run if runner is None else runner
        self._audit_lock = threading.Lock()
        self._local = threading.local()

    def _write_audit(self, **record):
        # ThreadingUnixStreamServer can execute several requests concurrently.
        with self._audit_lock:
            self.audit.write(**record)

    def _audit_rejection(self, pid, code):
        self._write_audit(pid=pid, error=code)

    def _status(self, symbol, text, code):
        if getattr(self._local, "shown", False):
            self.prompter.status(symbol, text, code)

    def delivered(self, sent):
        """Tell the owner whether the agent got the answer, then go idle."""
        if not getattr(self._local, "shown", False):
            return
        if sent:
            self._status("\u2713", "Response delivered to the agent", GREEN)
        else:
            self._status(
                "\u2717", "Agent disconnected - response not delivered", RED
            )
        self._local.shown = False
        self.prompter.idle()

    def handle(self, request, pid, parent_cmdline=None):
        self._local.shown = False
        if not isinstance(request, dict):
            self._audit_rejection(pid, "bad_request")
            return _error("bad_request", "invalid request")
        operation = request.get("op")
        if operation == "ls":
            return {"ok": True, "entries": self.vault.list()}
        if operation != "run":
            self._audit_rejection(pid, "bad_request")
            return _error("bad_request", "invalid request")

        values = _validate_run_request(request)
        if values is None:
            self._audit_rejection(pid, "bad_request")
            return _error("bad_request", "invalid request")

        normalized_cwd = _normalize_cwd(values["cwd"])
        if normalized_cwd is None:
            self._audit_rejection(pid, "bad_request")
            return _error("bad_request", "invalid request")
        values["cwd"] = normalized_cwd

        executable = _resolve_executable(
            values["argv"][0], values["cwd"], values["client_env"]
        )
        if executable is None:
            self._audit_rejection(pid, "executable_not_found")
            return _error(
                "executable_not_found", "requested executable is unavailable"
            )
        executable_identity = _executable_identity(executable)
        if executable_identity is None:
            self._audit_rejection(pid, "executable_not_found")
            return _error(
                "executable_not_found", "requested executable is unavailable"
            )

        references = values["env"]
        secrets = {}
        try:
            for name, reference in references.items():
                secrets[name] = self.vault.resolve(reference)
        except (Ambiguous, NoSuchEntry, NoSuchField):
            # Never echo a ref or a vault exception to the requesting process.
            self._audit_rejection(pid, "no_such_field")
            return _error("no_such_field", "requested field is unavailable")

        fields = frozenset(references.values())
        argv = tuple(values["argv"])
        cwd = values["cwd"]
        peer_cmdline = (
            parent_cmdline
            if parent_cmdline is not None
            else _parent_cmdline(pid)
        )
        prompt_request = {
            "pid": pid,
            "parent_cmdline": peer_cmdline,
            "cwd": values["cwd"],
            "exe": executable,
            "why": values["why"],
            "env": references,
            "argv": values["argv"],
            "warning": None,
        }
        if os.access(executable, os.W_OK) or os.access(
            os.path.dirname(executable), os.W_OK
        ):
            prompt_request["warning"] = (
                "The file or its directory is writable by the agent - "
                "an h grant does not protect against replacement."
            )

        granted = self.grants.check(
            fields, argv, cwd, executable, executable_identity
        )
        self._local.shown = True
        if granted:
            decision = "hour"
            self.prompter.notify_granted(prompt_request)
        else:
            decision = self.prompter.ask(prompt_request)
        if decision not in {"once", "hour"}:
            self._audit_run(
                prompt_request,
                decision="deny",
                exit_code=None,
                granted=granted,
            )
            return _error("denied", "request denied")
        if decision == "hour" and not granted:
            self.grants.add(
                fields,
                argv,
                cwd,
                executable,
                ttl=_HOUR_SECONDS,
                exe_identity=executable_identity,
            )

        short_refs = [
            references[name]
            for name, secret in secrets.items()
            if len(secret) < MIN_SECRET_LENGTH
        ]
        for reference in short_refs:
            self._write_audit(
                warning="short_secret_not_masked",
                ref=reference,
            )

        command_env = dict(values["client_env"])
        command_env.update(secrets)
        self._audit_run(
            prompt_request,
            decision=decision,
            exit_code=None,
            granted=granted,
        )
        output_limit = _MAX_OUTPUT_BYTES + max(
            (
                len(secret.encode("utf-8"))
                for secret in secrets.values()
                if len(secret) >= MIN_SECRET_LENGTH
            ),
            default=0,
        )
        try:
            if _executable_identity(executable) != executable_identity:
                self._audit_rejection(pid, "executable_changed")
                self._status(
                    "\u2717", "Executable changed after approval - not run", RED
                )
                return _error(
                    "executable_changed",
                    "requested executable changed after approval",
                )
            self._status("\u2022", "Running the command...", DIM)
            result = self.runner(
                argv,
                env=command_env,
                cwd=values["cwd"],
                timeout=values["timeout"],
                limit=output_limit,
                executable=executable,
            )
        except Exception:
            self._audit_run(
                prompt_request,
                decision=decision,
                exit_code=None,
                granted=granted,
                timed_out=None,
                runner_error=True,
            )
            self._status("\u2717", "Command could not be started", RED)
            return _error("internal_error", "request could not be completed")

        self._audit_run(
            prompt_request,
            decision=decision,
            exit_code=result.exit,
            granted=granted,
            timed_out=result.timed_out,
        )
        if result.timed_out:
            self._status(
                "\u2717",
                f"Command timed out after {values['timeout']}s and was stopped",
                RED,
            )
            return _error("timeout", "command timed out")
        if result.exit == 0:
            self._status("\u2713", "Command finished: exit code 0", GREEN)
        else:
            self._status(
                "\u2717", f"Command finished: exit code {result.exit}", YELLOW
            )

        stdout = mask(result.stdout, list(secrets.values()))
        stderr = mask(result.stderr, list(secrets.values()))
        truncated = result.truncated or (
            len(stdout) > _MAX_OUTPUT_BYTES or len(stderr) > _MAX_OUTPUT_BYTES
        )
        stdout = stdout[:_MAX_OUTPUT_BYTES]
        stderr = stderr[:_MAX_OUTPUT_BYTES]
        return {
            "ok": True,
            "decision": decision,
            "exit": result.exit,
            "stdout_b64": base64.b64encode(stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(stderr).decode("ascii"),
            "truncated": truncated,
        }

    def _audit_run(
        self,
        prompt_request,
        decision,
        exit_code,
        granted,
        timed_out=None,
        runner_error=False,
    ):
        record = dict(
            pid=prompt_request["pid"],
            parent_cmdline=prompt_request["parent_cmdline"],
            cwd=prompt_request["cwd"],
            exe=prompt_request["exe"],
            why=prompt_request["why"],
            env=prompt_request["env"],
            argv=prompt_request["argv"],
            decision=decision,
            exit=exit_code,
            granted=granted,
        )
        if timed_out is not None:
            record["timed_out"] = timed_out
        if runner_error:
            record["runner_error"] = True
        self._write_audit(**record)


def default_socket_path(environ=None):
    environ = os.environ if environ is None else environ
    configured = environ.get("PASSBRO_SOCK")
    if configured:
        return Path(configured).expanduser()
    runtime_dir = environ.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        raise RuntimeError("XDG_RUNTIME_DIR is not set")
    return Path(runtime_dir) / "passbro" / "agent.sock"


def default_log_path(environ=None):
    environ = os.environ if environ is None else environ
    configured = environ.get("PASSBRO_LOG")
    if configured:
        return Path(configured).expanduser()
    return Path("~/.local/state/passbro/log.jsonl").expanduser()


def _ensure_socket_directory(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not stat.S_ISDIR(path.parent.lstat().st_mode):
        raise RuntimeError("socket directory is not a directory")
    os.chmod(path.parent, 0o700)


def _remove_stale_socket(path):
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(current.st_mode):
        raise RuntimeError("socket path exists and is not a socket")

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(os.fspath(path))
    except OSError as error:
        if error.errno == errno.ENOENT:
            return
        if error.errno != errno.ECONNREFUSED:
            raise RuntimeError("cannot connect to existing socket") from None
        try:
            latest = path.lstat()
        except FileNotFoundError:
            return
        if (latest.st_dev, latest.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError("socket path changed during startup")
        path.unlink()
    else:
        raise RuntimeError("passbro agent already running")
    finally:
        probe.close()


class BrokerRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(_REQUEST_TIMEOUT_SECONDS)
        try:
            pid, uid, _gid = _peer_credentials(self.request)
        except OSError:
            self._drain_request()
            self._send(_error("denied", "peer credentials unavailable"))
            return
        if uid != os.getuid():
            self._drain_request()
            self._send(_error("denied", "peer uid is not allowed"))
            return

        try:
            line = self.rfile.readline(_MAX_REQUEST_BYTES + 1)
        except (OSError, ValueError):
            self._drain_request()
            self._audit_rejection(pid, "bad_request")
            self._send(_error("bad_request", "invalid request"))
            return
        if (
            len(line) > _MAX_REQUEST_BYTES
            or not line.endswith(b"\n")
        ):
            self._drain_request()
            self._audit_rejection(pid, "bad_request")
            self._send(_error("bad_request", "invalid request"))
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._audit_rejection(pid, "bad_request")
            self._send(_error("bad_request", "invalid request"))
            return

        try:
            response = self.server.broker.handle(
                request,
                pid,
                parent_cmdline=_parent_cmdline(pid),
            )
        except Exception:
            # Avoid returning exception text that might contain request data.
            response = _error("internal_error", "request could not be completed")
        self.server.broker.delivered(self._send(response))

    def _drain_request(self):
        previous_timeout = self.connection.gettimeout()
        self.connection.settimeout(_DRAIN_TIMEOUT_SECONDS)
        remaining = _MAX_DRAIN_BYTES
        try:
            while remaining > 0:
                chunk = self.rfile.readline(min(remaining, _DRAIN_CHUNK_BYTES))
                if not chunk:
                    break
                remaining -= len(chunk)
                if chunk.endswith(b"\n"):
                    break
        except (OSError, ValueError):
            pass
        finally:
            self.connection.settimeout(previous_timeout)

    def _audit_rejection(self, pid, code):
        self.server.broker._audit_rejection(pid, code)

    def _send(self, response):
        try:
            payload = (
                json.dumps(response, ensure_ascii=False, allow_nan=False) + "\n"
            ).encode("utf-8")
            self.wfile.write(payload)
            self.wfile.flush()
        except (OSError, ValueError):
            return False
        return True


class BrokerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, socket_path, broker):
        self.broker = broker
        self._error_lock = threading.Lock()
        super().__init__(
            os.fspath(socket_path),
            BrokerRequestHandler,
            bind_and_activate=False,
        )

    def handle_error(self, request, client_address):
        with self._error_lock:
            sys.stderr.write("passbro: request handler failed\n")
            sys.stderr.flush()


def create_server(socket_path, broker):
    """Create a bound broker server and secure its directory and socket."""
    path = Path(socket_path).expanduser()
    _ensure_socket_directory(path)
    _remove_stale_socket(path)

    server = BrokerServer(path, broker)
    bound_stat = None
    try:
        server.server_bind()
        bound_stat = path.lstat()
        os.chmod(path, 0o600)
        server.server_activate()
    except BaseException:
        server.server_close()
        if bound_stat is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (
                    bound_stat.st_dev,
                    bound_stat.st_ino,
                ):
                    path.unlink()
            except FileNotFoundError:
                pass
        raise
    server.socket_path = path
    server._socket_identity = (bound_stat.st_dev, bound_stat.st_ino)
    return server


def serve(
    vault, socket_path=None, prompter=None, grants=None, audit=None, on_ready=None
):
    """Serve until interrupted, then close the listener and remove its socket.

    ``on_ready(socket_path)`` is called once the socket accepts connections.
    """
    if socket_path is None:
        socket_path = default_socket_path()
    if audit is None:
        audit = audit_module.Audit(default_log_path())
    broker = Broker(vault, prompter=prompter, grants=grants, audit=audit)
    server = create_server(socket_path, broker)
    try:
        if on_ready is not None:
            on_ready(server.socket_path)
        server.serve_forever()
    finally:
        server.server_close()
        try:
            current = server.socket_path.lstat()
            if (current.st_dev, current.st_ino) == server._socket_identity:
                server.socket_path.unlink()
        except FileNotFoundError:
            pass
