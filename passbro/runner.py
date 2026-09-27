"""Run a command with bounded output capture and process-group timeouts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
import selectors
import signal
import stat
import subprocess
import time
from typing import BinaryIO


_READ_SIZE = 64 * 1024
_TERM_GRACE_SECONDS = 5
_KILL_GRACE_SECONDS = 1
_SELECT_INTERVAL_SECONDS = 0.1


@dataclass(frozen=True)
class Result:
    """Captured result of one command invocation.

    ``stdout`` and ``stderr`` are bytes so callers can preserve arbitrary
    command output and encode it for the broker protocol without decoding it.
    ``exit`` is the subprocess return code, including negative signal codes.
    ``timed_out`` can be true with ``exit == 0`` when the command exited
    successfully but a descendant kept an inherited output pipe open past the
    timeout.
    """

    exit: int
    stdout: bytes
    stderr: bytes
    truncated: bool
    timed_out: bool


def _signal_process_group(process: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except OSError:
        pass


def _error_result(exit_code: int, message: str, limit: int) -> Result:
    encoded = message.encode("utf-8", errors="replace")
    return Result(
        exit=exit_code,
        stdout=b"",
        stderr=encoded[:limit],
        truncated=len(encoded) > limit,
        timed_out=False,
    )


def _unregister_and_close(
    selector: selectors.BaseSelector, stream: BinaryIO
) -> None:
    try:
        selector.unregister(stream)
    except (KeyError, ValueError):
        pass
    stream.close()


def _close_handles(
    selector: selectors.BaseSelector | None, streams: Sequence[BinaryIO]
) -> None:
    try:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                pass
    finally:
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass


def run(
    argv: Sequence[str],
    env: Mapping[str, str] | None,
    cwd: str | os.PathLike[str] | None,
    timeout: float,
    limit: int,
    *,
    executable: str | os.PathLike[str] | None = None,
) -> Result:
    """Run ``argv``, retaining at most ``limit`` bytes from each output stream.

    A missing or non-directory working directory returns exit 126 with a
    diagnostic. A missing executable returns 127; permission denied while
    starting returns 126.
    Other ``OSError`` exceptions from checking the working directory or
    starting the process propagate to the caller. ``timed_out`` also becomes
    true if the direct child exits but a descendant keeps an output pipe open
    past the timeout. If a timed-out process does not exit after ``SIGKILL``,
    ``run`` waits for it without a time limit.
    """
    if not argv:
        raise ValueError("argv must contain a command")
    if timeout < 0:
        raise ValueError("timeout must not be negative")
    if limit < 0:
        raise ValueError("limit must not be negative")

    cwd_arg = None if cwd is None else os.fspath(cwd)
    cwd_display = None if cwd_arg is None else os.fsdecode(cwd_arg)
    if cwd_arg is not None:
        try:
            cwd_stat = os.stat(cwd_arg)
        except FileNotFoundError:
            return _error_result(
                126,
                f"passbro: working directory not found: {cwd_display}\n",
                limit,
            )
        except NotADirectoryError:
            return _error_result(
                126,
                f"passbro: working directory is not a directory: {cwd_display}\n",
                limit,
            )
        except PermissionError:
            return _error_result(
                126,
                f"passbro: permission denied accessing working directory: {cwd_display}\n",
                limit,
            )
        if not stat.S_ISDIR(cwd_stat.st_mode):
            return _error_result(
                126,
                f"passbro: working directory is not a directory: {cwd_display}\n",
                limit,
            )

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=None if env is None else dict(env),
            cwd=cwd_arg,
            executable=executable,
            start_new_session=True,
            bufsize=0,
        )
    except FileNotFoundError:
        # The directory can disappear between the check above and Popen.
        if cwd_arg is not None:
            try:
                os.stat(cwd_arg)
            except FileNotFoundError:
                return _error_result(
                    126,
                    f"passbro: working directory not found: {cwd_display}\n",
                    limit,
                )
            except NotADirectoryError:
                return _error_result(
                    126,
                    f"passbro: working directory is not a directory: {cwd_display}\n",
                    limit,
                )
            except PermissionError:
                return _error_result(
                    126,
                    f"passbro: permission denied accessing working directory: {cwd_display}\n",
                    limit,
                )
        command = os.fsdecode(os.fspath(argv[0]))
        return _error_result(127, f"passbro: command not found: {command}\n", limit)
    except PermissionError:
        command = os.fsdecode(os.fspath(argv[0]))
        return _error_result(
            126,
            f"passbro: permission denied starting command: {command}\n",
            limit,
        )

    stdout = process.stdout
    stderr = process.stderr
    assert stdout is not None
    assert stderr is not None
    pipe_streams = (stdout, stderr)

    selector: selectors.BaseSelector | None = None
    try:
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = False
        timed_out = False
        term_sent_at: float | None = None
        kill_sent_at: float | None = None
        started_at = time.monotonic()
        selector = selectors.DefaultSelector()
        streams = {
            stdout.fileno(): (stdout, "stdout"),
            stderr.fileno(): (stderr, "stderr"),
        }
        for fd, (stream, _name) in streams.items():
            os.set_blocking(fd, False)
            selector.register(stream, selectors.EVENT_READ)

        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            # Keep the timeout active while inherited pipe handles remain open,
            # even if the direct child has already exited.
            if (
                not timed_out
                and now - started_at >= timeout
                and (process.poll() is None or selector.get_map())
            ):
                timed_out = True
                term_sent_at = now
                _signal_process_group(process, signal.SIGTERM)

            if (
                timed_out
                and kill_sent_at is None
                and term_sent_at is not None
                and now - term_sent_at >= _TERM_GRACE_SECONDS
            ):
                _signal_process_group(process, signal.SIGKILL)
                kill_sent_at = now

            if (
                kill_sent_at is not None
                and now - kill_sent_at >= _KILL_GRACE_SECONDS
            ):
                for key in list(selector.get_map().values()):
                    _unregister_and_close(selector, key.fileobj)

            wait_for = _SELECT_INTERVAL_SECONDS
            if not timed_out:
                wait_for = min(wait_for, max(0.0, timeout - (now - started_at)))
            elif kill_sent_at is None and term_sent_at is not None:
                wait_for = min(
                    wait_for,
                    max(0.0, _TERM_GRACE_SECONDS - (now - term_sent_at)),
                )
            elif kill_sent_at is not None:
                wait_for = min(
                    wait_for,
                    max(0.0, _KILL_GRACE_SECONDS - (now - kill_sent_at)),
                )

            if selector.get_map():
                events = selector.select(wait_for)
            elif (
                kill_sent_at is not None
                and now - kill_sent_at >= _KILL_GRACE_SECONDS
            ):
                process.wait()
                events = ()
            else:
                try:
                    process.wait(timeout=wait_for)
                except subprocess.TimeoutExpired:
                    pass
                events = ()

            for key, _mask in events:
                stream = key.fileobj
                fd = stream.fileno()
                name = streams[fd][1]
                try:
                    data = os.read(fd, _READ_SIZE)
                except BlockingIOError:
                    continue

                if not data:
                    _unregister_and_close(selector, stream)
                    continue

                remaining = limit - len(captured[name])
                if remaining > 0:
                    captured[name].extend(data[:remaining])
                if len(data) > max(remaining, 0):
                    truncated = True

        returncode = process.wait()
    except BaseException:
        try:
            _signal_process_group(process, signal.SIGKILL)
        finally:
            try:
                process.wait()
            finally:
                _close_handles(selector, pipe_streams)
        raise
    else:
        _close_handles(selector, pipe_streams)

    return Result(
        exit=returncode,
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
        truncated=truncated,
        timed_out=timed_out,
    )
