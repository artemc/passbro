"""Client for the local passbro agent."""

import json
import math
import os
from pathlib import Path
import socket


_PROMPT_TIMEOUT_SECONDS = 120
_RESPONSE_RESERVE_SECONDS = 10
_LS_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class AgentUnavailable(Exception):
    """The local agent socket could not be reached."""


class ClientError(Exception):
    """The agent connection did not produce a valid protocol response."""


def default_socket_path(environ=None):
    """Return the agent socket path from PASSBRO_SOCK or XDG_RUNTIME_DIR."""
    environ = os.environ if environ is None else environ
    configured = environ.get("PASSBRO_SOCK")
    if configured:
        return Path(configured).expanduser()
    runtime_dir = environ.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        raise RuntimeError("XDG_RUNTIME_DIR is not set")
    return Path(runtime_dir) / "passbro" / "agent.sock"


def _response_timeout(request):
    """Return the socket timeout used while connecting and sending."""
    if request.get("op") != "run":
        return _LS_TIMEOUT_SECONDS
    command_timeout = request.get("timeout", 600)
    if (
        isinstance(command_timeout, bool)
        or not isinstance(command_timeout, (int, float))
        or command_timeout < 0
        or command_timeout > 600
        or not math.isfinite(command_timeout)
    ):
        raise ValueError("invalid command timeout")
    return (
        _PROMPT_TIMEOUT_SECONDS
        + command_timeout
        + _RESPONSE_RESERVE_SECONDS
    )


def request(payload, *, socket_path=None):
    """Send one protocol request and return the decoded JSON response."""
    if socket_path is None:
        try:
            socket_path = default_socket_path()
        except (OSError, RuntimeError, ValueError):
            raise AgentUnavailable from None

    try:
        response_timeout = _response_timeout(payload)
    except (AttributeError, TypeError, ValueError):
        raise ClientError("invalid request") from None

    try:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ClientError("invalid request") from None

    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        raise AgentUnavailable from None
    try:
        connection.settimeout(response_timeout)
        try:
            connection.connect(os.fspath(socket_path))
        except OSError:
            raise AgentUnavailable from None

        try:
            connection.sendall(encoded)
            connection.settimeout(None)
            response_bytes = bytearray()
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response_bytes.extend(chunk)
                if len(response_bytes) > _MAX_RESPONSE_BYTES:
                    raise ClientError("oversized response")
                newline = response_bytes.find(b"\n")
                if newline >= 0:
                    if newline != len(response_bytes) - 1:
                        raise ClientError("invalid response")
                    break
        except ClientError:
            raise
        except OSError:
            raise ClientError("communication failed") from None
    finally:
        connection.close()

    if not response_bytes or response_bytes[-1:] != b"\n":
        raise ClientError("empty or incomplete response")
    try:
        response = json.loads(response_bytes[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ClientError("invalid response") from None
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise ClientError("invalid response")
    return response


def run(why, env, argv, timeout=600, *, socket_path=None):
    """Ask the agent to run argv with the requested KeePass fields."""
    payload = {
        "op": "run",
        "why": why,
        "env": dict(env),
        "argv": list(argv),
        "cwd": os.getcwd(),
        "client_env": dict(os.environ),
        "timeout": timeout,
    }
    return request(payload, socket_path=socket_path)


def ls(*, socket_path=None):
    """List entry paths and field names from the agent."""
    return request({"op": "ls"}, socket_path=socket_path)
