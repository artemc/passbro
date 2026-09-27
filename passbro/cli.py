import argparse
import base64
import math
import os
from getpass import getpass
from pathlib import Path
import sys

from passbro import __version__, client, term


_BROKER_ERRORS = frozenset(
    {
        "denied",
        "timeout",
        "no_such_field",
        "executable_not_found",
        "executable_changed",
        "bad_request",
        "internal_error",
    }
)


def _timeout_value(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a number") from None
    if not math.isfinite(timeout) or not 0 <= timeout <= 600:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 600")
    return int(timeout) if timeout.is_integer() else timeout


def _parser():
    parser = argparse.ArgumentParser(prog="passbro")
    parser.add_argument("--version", action="version", version=f"passbro {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    agent = commands.add_parser("agent")
    agent.add_argument("--db", required=True)

    run = commands.add_parser("run")
    run.add_argument("--why", required=True)
    run.add_argument("-e", dest="env_assignments", action="append", required=True)
    run.add_argument("--timeout", type=_timeout_value, default=600)

    commands.add_parser("ls")
    return parser


_PASSWORD_ATTEMPTS = 3


def _status(mark, text, code):
    color = term.use_color(sys.stderr)
    print(term.status_line(mark, text, code, color), file=sys.stderr, flush=True)


def _run_agent(database_path):
    from pykeepass.exceptions import CredentialsError

    from passbro.audit import Audit
    from passbro.broker import default_log_path, serve
    from passbro.console import Console
    from passbro.grants import Grants
    from passbro.prompt import IDLE_TEXT, Prompter
    from passbro.vault import Vault

    path = Path(database_path).expanduser()
    if not path.is_file():
        raise RuntimeError(f"database not found: {path}")
    _status("\u2022", f"Database: {path}", term.DIM)

    for attempt in range(1, _PASSWORD_ATTEMPTS + 1):
        password = getpass("KeePass master password: ")
        _status("\u2022", "Unlocking database...", term.DIM)
        try:
            vault = Vault.open(path, password)
            break
        except CredentialsError:
            left = _PASSWORD_ATTEMPTS - attempt
            _status(
                "\u2717",
                f"Wrong master password ({left} attempts left)"
                if left
                else "Wrong master password",
                term.RED,
            )
    else:
        raise RuntimeError("too many wrong passwords")

    _status("\u2713", f"Database unlocked: {len(vault.list())} entries", term.GREEN)

    prompter = Prompter(input=sys.stdin, output=sys.stderr)
    grants = Grants()
    log_path = default_log_path()

    def ready(socket_path):
        _status("\u2713", f"Listening on {socket_path}", term.GREEN)
        _status(
            "\u2022",
            IDLE_TEXT,
            term.CYAN,
        )
        Console(prompter, grants, log_path, sys.stderr).start()

    try:
        serve(
            vault,
            prompter=prompter,
            grants=grants,
            audit=Audit(log_path),
            on_ready=ready,
        )
    except KeyboardInterrupt:
        print(file=sys.stderr)
        _status("\u2022", "passbro agent stopped", term.DIM)
        raise


def _run_environment(assignments):
    env = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise ValueError("each -e value must have the form VAR=ref")
        name, reference = assignment.split("=", 1)
        if not name or not reference or "\0" in name or "\0" in reference:
            raise ValueError("each -e value must have the form VAR=ref")
        env[name] = reference
    return env


def _write_bytes(stream, data):
    binary_stream = getattr(stream, "buffer", None)
    if binary_stream is not None:
        binary_stream.write(data)
        binary_stream.flush()
        return
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(data.decode(encoding, errors="replace"))
    stream.flush()


def _silence_broken_stream(stream, name):
    try:
        stream_fd = stream.fileno()
        null_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null_fd, stream_fd)
        finally:
            os.close(null_fd)
    except (AttributeError, OSError, ValueError):
        setattr(sys, name, None)


def _write_output(name, data):
    try:
        _write_bytes(getattr(sys, name), data)
    except BrokenPipeError:
        _silence_broken_stream(getattr(sys, name), name)
        return False
    return True


def _broker_error(response):
    error = response.get("error")
    message = response.get("message")
    if isinstance(error, str) and error in _BROKER_ERRORS:
        text = message if isinstance(message, str) and message else error
    elif isinstance(message, str) and message:
        text = message
    else:
        text = "passbro agent returned an error"
    print(text, file=sys.stderr)


def _run_command(args, command_argv):
    try:
        env = _run_environment(args.env_assignments)
        response = client.run(
            args.why,
            env,
            command_argv,
            timeout=args.timeout,
        )
    except ValueError as error:
        print(f"passbro run: {error}", file=sys.stderr)
        return 2
    except client.AgentUnavailable:
        print("passbro agent is not running", file=sys.stderr)
        return 2
    except client.ClientError:
        print("passbro run: communication error with passbro agent", file=sys.stderr)
        return 1
    except OSError:
        print("passbro run: cannot determine current directory", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(
            "passbro run: wait interrupted; the command may still run",
            file=sys.stderr,
        )
        return 130

    if not response["ok"]:
        _broker_error(response)
        return 1
    try:
        stdout = base64.b64decode(response["stdout_b64"], validate=True)
        stderr = base64.b64decode(response["stderr_b64"], validate=True)
        exit_code = response["exit"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        print("passbro run: invalid response from passbro agent", file=sys.stderr)
        return 1

    stdout_ok = _write_output("stdout", stdout)
    stderr_ok = _write_output("stderr", stderr)
    if response.get("truncated") is True:
        warning = "passbro: output truncated\n".encode("utf-8")
        if stderr and not stderr.endswith(b"\n"):
            warning = b"\n" + warning
        stderr_ok = _write_output("stderr", warning) and stderr_ok
    if not stdout_ok or not stderr_ok:
        return 1
    return 128 - exit_code if exit_code < 0 else exit_code


def _list_entries():
    try:
        response = client.ls()
    except client.AgentUnavailable:
        print("passbro agent is not running", file=sys.stderr)
        return 2
    except client.ClientError:
        print("passbro ls: communication error with passbro agent", file=sys.stderr)
        return 1

    if not response["ok"]:
        _broker_error(response)
        return 1
    entries = response.get("entries")
    if not isinstance(entries, list):
        print("passbro ls: invalid response from passbro agent", file=sys.stderr)
        return 1
    addresses = []
    for entry in entries:
        if not isinstance(entry, dict):
            print("passbro ls: invalid response from passbro agent", file=sys.stderr)
            return 1
        path = entry.get("path")
        fields = entry.get("fields")
        if (
            not isinstance(path, str)
            or not isinstance(fields, list)
            or not all(isinstance(field, str) for field in fields)
        ):
            print("passbro ls: invalid response from passbro agent", file=sys.stderr)
            return 1
        addresses.extend(f"{path}/{field}" for field in fields)
    if addresses:
        sys.stdout.write("".join(f"{address}\n" for address in addresses))
        sys.stdout.flush()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command_argv = None
    if argv and argv[0] == "run":
        try:
            separator = argv.index("--", 1)
        except ValueError:
            separator = None
        if separator is None:
            args = _parse_args(argv)
            if args is None:
                return 0
            _parser().error("run requires '-- cmd...' after its options")
        args = _parse_args(argv[:separator])
        if args is None:
            return 0
        command_argv = argv[separator + 1 :]
        if not command_argv:
            _parser().error("run requires a command after '--'")
        argv = argv[:separator]

    else:
        args = _parse_args(argv)
        if args is None:
            return 0
    if args.command == "agent":
        try:
            _run_agent(args.db)
        except KeyboardInterrupt:
            return 0
        except Exception as error:
            _status("\u2717", f"passbro agent: {error}", term.RED)
            return 2
        return 0
    if args.command == "run":
        return _run_command(args, command_argv)
    return _list_entries()


def _parse_args(argv):
    try:
        return _parser().parse_args(argv)
    except SystemExit as error:
        if error.code == 0:
            return None
        raise
