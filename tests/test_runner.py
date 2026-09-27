import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from passbro.runner import run


class RunnerTests(unittest.TestCase):
    def test_captures_both_streams_and_exit_code(self):
        result = run(
            ["sh", "-c", "printf 'out'; printf 'err' >&2; exit 7"],
            env=os.environ.copy(),
            cwd=None,
            timeout=5,
            limit=1024,
        )

        self.assertEqual(result.exit, 7)
        self.assertEqual(result.stdout, b"out")
        self.assertEqual(result.stderr, b"err")
        self.assertFalse(result.truncated)
        self.assertFalse(result.timed_out)

    def test_timeout_terminates_process_group_after_term_grace(self):
        code = (
            "import signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); "
            "time.sleep(30)"
        )
        with patch("passbro.runner._TERM_GRACE_SECONDS", 0.1):
            result = run(
                [sys.executable, "-c", code],
                env=os.environ.copy(),
                cwd=None,
                timeout=2,
                limit=1024,
            )

        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit, -signal.SIGKILL)
        self.assertEqual(result.stdout, b"ready\n")

    def test_timeout_returns_when_detached_descendant_holds_output_pipe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_file = Path(temp_dir) / "detached.pid"
            child_script = (
                f"echo $$ > {shlex.quote(str(pid_file))}; exec sleep 30"
            )
            script = f"setsid -f sh -c {shlex.quote(child_script)} & echo hi"
            try:
                with (
                    patch("passbro.runner._TERM_GRACE_SECONDS", 0.1),
                    patch("passbro.runner._KILL_GRACE_SECONDS", 0.1),
                ):
                    started = time.monotonic()
                    result = run(
                        ["sh", "-c", script],
                        env=os.environ.copy(),
                        cwd=None,
                        timeout=0.2,
                        limit=1024,
                    )
                    elapsed = time.monotonic() - started

                self.assertTrue(result.timed_out)
                self.assertEqual(result.stdout, b"hi\n")
                self.assertEqual(result.exit, 0)
                self.assertLess(elapsed, 2)
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_timeout_terminates_background_process_group(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_file = Path(temp_dir) / "grandchild.pid"
            script = (
                f"trap 'wait; exit 0' TERM; sleep 30 & "
                f"echo $! > {shlex.quote(str(pid_file))}; echo ready; wait"
            )
            with patch("passbro.runner._TERM_GRACE_SECONDS", 0.1):
                result = run(
                    ["sh", "-c", script],
                    env=os.environ.copy(),
                    cwd=None,
                    timeout=0.5,
                    limit=1024,
                )

            child_pid = int(pid_file.read_text())
            try:
                self.assertTrue(result.timed_out)
                self.assertEqual(result.stdout, b"ready\n")
                deadline = time.monotonic() + 2
                while True:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail(
                            "background process survived process-group timeout"
                        )
                    time.sleep(0.01)
            finally:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_timeout_can_return_direct_child_sigterm_status(self):
        result = run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=os.environ.copy(),
            cwd=None,
            timeout=0.5,
            limit=1024,
        )

        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit, -signal.SIGTERM)

    def test_caps_each_stream_and_continues_draining_both(self):
        code = (
            "import os; "
            "os.write(1, b'o' * 100000); "
            "os.write(2, b'e' * 100000)"
        )
        result = run(
            [sys.executable, "-c", code],
            env=os.environ.copy(),
            cwd=None,
            timeout=5,
            limit=4,
        )

        self.assertEqual(result.exit, 0)
        self.assertEqual(result.stdout, b"oooo")
        self.assertEqual(result.stderr, b"eeee")
        self.assertTrue(result.truncated)
        self.assertFalse(result.timed_out)

    def test_passes_environment_to_command(self):
        child_env = os.environ.copy()
        child_env["PASSBRO_RUNNER_TEST"] = "reached-child"
        result = run(
            ["sh", "-c", "printf '%s' \"$PASSBRO_RUNNER_TEST\""],
            env=child_env,
            cwd=None,
            timeout=5,
            limit=1024,
        )

        self.assertEqual(result.exit, 0)
        self.assertEqual(result.stdout, b"reached-child")

    def test_executable_override_keeps_original_argv0(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            alias = Path(temp_dir) / "shell-alias"
            alias.symlink_to("/bin/sh")
            argv = [str(alias), "-c", "printf '%s' \"$0\""]

            result = run(
                argv,
                env=os.environ.copy(),
                cwd=temp_dir,
                timeout=5,
                limit=1024,
                executable=os.path.realpath(alias),
            )

        self.assertEqual(result.exit, 0)
        self.assertEqual(result.stdout, str(alias).encode())

    def test_stdin_is_devnull(self):
        result = run(
            ["cat"],
            env=os.environ.copy(),
            cwd=None,
            timeout=5,
            limit=1024,
        )

        self.assertEqual(result.exit, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_uses_requested_working_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run(
                ["pwd"],
                env=os.environ.copy(),
                cwd=temp_dir,
                timeout=5,
                limit=1024,
            )

        self.assertEqual(result.exit, 0)
        self.assertEqual(result.stdout, f"{Path(temp_dir).resolve()}\n".encode())

    def test_missing_command_returns_127_and_message(self):
        result = run(
            ["passbro-command-that-does-not-exist"],
            env=os.environ.copy(),
            cwd=None,
            timeout=5,
            limit=1024,
        )

        self.assertEqual(result.exit, 127)
        self.assertIn(b"command not found", result.stderr)
        self.assertFalse(result.truncated)
        self.assertFalse(result.timed_out)

    def test_missing_command_message_obeys_output_limit(self):
        result = run(
            ["passbro-command-that-does-not-exist"],
            env=os.environ.copy(),
            cwd=None,
            timeout=5,
            limit=4,
        )

        self.assertEqual(len(result.stderr), 4)
        self.assertTrue(result.truncated)

    def test_missing_working_directory_has_distinct_bounded_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_dir = Path(temp_dir) / "not-here"
            result = run(
                ["sh", "-c", "exit 0"],
                env=os.environ.copy(),
                cwd=missing_dir,
                timeout=5,
                limit=40,
            )

        self.assertEqual(result.exit, 126)
        self.assertIn(b"working directory not found", result.stderr)
        self.assertEqual(len(result.stderr), 40)
        self.assertTrue(result.truncated)
        self.assertFalse(result.timed_out)

    def test_non_executable_file_returns_126_and_bounded_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            command = Path(temp_dir) / "not-executable"
            command.write_text("#!/bin/sh\nexit 0\n")
            command.chmod(0o600)
            result = run(
                [str(command)],
                env=os.environ.copy(),
                cwd=None,
                timeout=5,
                limit=60,
            )

        self.assertEqual(result.exit, 126)
        self.assertIn(b"permission denied", result.stderr)
        self.assertEqual(len(result.stderr), 60)
        self.assertTrue(result.truncated)
        self.assertFalse(result.timed_out)

    def test_exception_kills_child_and_closes_output_pipes(self):
        child_processes = []
        real_popen = subprocess.Popen
        real_read = os.read

        def capture_process(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            child_processes.append(process)
            return process

        def fail_on_output_pipe(fd, size):
            for process in child_processes:
                if fd in (process.stdout.fileno(), process.stderr.fileno()):
                    raise RuntimeError("read failed")
            return real_read(fd, size)

        code = (
            "import os, signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "os.write(1, b'ready'); time.sleep(30)"
        )
        with patch("passbro.runner.subprocess.Popen", side_effect=capture_process):
            with patch("passbro.runner.os.read", side_effect=fail_on_output_pipe):
                with self.assertRaisesRegex(RuntimeError, "read failed"):
                    run(
                        [sys.executable, "-c", code],
                        env=os.environ.copy(),
                        cwd=None,
                        timeout=5,
                        limit=1024,
                    )

        self.assertEqual(len(child_processes), 1)
        self.assertIsNotNone(child_processes[0].poll())
        self.assertTrue(child_processes[0].stdout.closed)
        self.assertTrue(child_processes[0].stderr.closed)

    def test_empty_selector_waits_for_child_without_spinning(self):
        started = time.monotonic()
        cpu_started = time.process_time()
        result = run(
            ["sh", "-c", "exec >&- 2>&-; sleep 1"],
            env=os.environ.copy(),
            cwd=None,
            timeout=3,
            limit=1024,
        )
        cpu_elapsed = time.process_time() - cpu_started
        elapsed = time.monotonic() - started

        self.assertEqual(result.exit, 0)
        self.assertFalse(result.timed_out)
        self.assertGreaterEqual(elapsed, 0.8)
        self.assertLess(elapsed, 2)
        self.assertLess(cpu_elapsed, 0.3)

    def test_after_kill_grace_waits_without_spinning_for_child(self):
        script = (
            "exec >&- 2>&-; "
            "sleep 30 & child=$!; "
            "(sleep 1; kill -KILL \"$child\") & "
            "wait \"$child\"; wait"
        )
        started = time.monotonic()
        cpu_started = time.process_time()
        with (
            patch("passbro.runner._TERM_GRACE_SECONDS", 0.05),
            patch("passbro.runner._KILL_GRACE_SECONDS", 0.05),
            patch("passbro.runner._signal_process_group"),
        ):
            result = run(
                ["sh", "-c", script],
                env=os.environ.copy(),
                cwd=None,
                timeout=0.05,
                limit=1024,
            )
        cpu_elapsed = time.process_time() - cpu_started
        elapsed = time.monotonic() - started

        self.assertTrue(result.timed_out)
        self.assertGreaterEqual(elapsed, 0.8)
        self.assertLess(elapsed, 2)
        self.assertLess(cpu_elapsed, 0.3)

    def test_signal_permission_error_keeps_timeout_timers_running(self):
        with (
            patch("passbro.runner._TERM_GRACE_SECONDS", 0.05),
            patch("passbro.runner._KILL_GRACE_SECONDS", 0.05),
            patch(
                "passbro.runner.os.killpg",
                side_effect=PermissionError("signal denied"),
            ) as killpg,
        ):
            result = run(
                ["sh", "-c", "sleep 0.3"],
                env=os.environ.copy(),
                cwd=None,
                timeout=0.05,
                limit=1024,
            )

        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit, 0)
        self.assertEqual(
            [call.args[1] for call in killpg.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )

    def test_permission_error_during_exception_cleanup_preserves_error(self):
        child_processes = []
        real_popen = subprocess.Popen
        real_read = os.read

        def capture_process(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            child_processes.append(process)
            return process

        def fail_on_output_pipe(fd, size):
            for process in child_processes:
                if fd in (process.stdout.fileno(), process.stderr.fileno()):
                    raise RuntimeError("read failed")
            return real_read(fd, size)

        code = "import os, time; os.write(1, b'ready'); time.sleep(0.1)"
        with (
            patch("passbro.runner.subprocess.Popen", side_effect=capture_process),
            patch("passbro.runner.os.read", side_effect=fail_on_output_pipe),
            patch(
                "passbro.runner.os.killpg",
                side_effect=PermissionError("signal denied"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "read failed"):
                run(
                    [sys.executable, "-c", code],
                    env=os.environ.copy(),
                    cwd=None,
                    timeout=5,
                    limit=1024,
                )

        self.assertEqual(len(child_processes), 1)
        self.assertIsNotNone(child_processes[0].poll())
        self.assertTrue(child_processes[0].stdout.closed)
        self.assertTrue(child_processes[0].stderr.closed)


if __name__ == "__main__":
    unittest.main()
