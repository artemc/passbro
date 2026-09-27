import threading
import unittest

from passbro.grants import Grants


class GrantsTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.grants = Grants(clock=lambda: self.now)
        self.fields = frozenset({"password", "username"})
        self.argv = ("deploy", "--environment", "staging")
        self.cwd = "/home/runner"
        self.exe = "/usr/bin/deploy"

    def test_exact_grant_key_matches(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertTrue(
            self.grants.check(self.fields, self.argv, self.cwd, self.exe)
        )

    def test_different_argv_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                self.fields,
                ("deploy", "--environment", "prod"),
                self.cwd,
                self.exe,
            )
        )

    def test_different_fields_do_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                frozenset({"password"}), self.argv, self.cwd, self.exe
            )
        )

    def test_requesting_more_fields_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                self.fields | {"url"}, self.argv, self.cwd, self.exe
            )
        )

    def test_argv_with_extra_suffix_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                self.fields, (*self.argv, "--force"), self.cwd, self.exe
            )
        )

    def test_argv_with_extra_prefix_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                self.fields, ("sudo", *self.argv), self.cwd, self.exe
            )
        )

    def test_list_input_on_add_matches_tuple_input_on_check(self):
        self.grants.add(
            list(self.fields), list(self.argv), self.cwd, self.exe, ttl=60
        )

        self.assertTrue(
            self.grants.check(
                tuple(self.fields), tuple(self.argv), self.cwd, self.exe
            )
        )

    def test_list_input_on_check_is_normalized(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertTrue(
            self.grants.check(
                list(self.fields), list(self.argv), self.cwd, self.exe
            )
        )

    def test_different_cwd_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(self.fields, self.argv, "/tmp/other", self.exe)
        )

    def test_different_executable_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)

        self.assertFalse(
            self.grants.check(
                self.fields, self.argv, self.cwd, "/opt/other/deploy"
            )
        )

    def test_different_executable_identity_does_not_match(self):
        self.grants.add(
            self.fields,
            self.argv,
            self.cwd,
            self.exe,
            ttl=60,
            exe_identity=(1, 2, 3, 4, 5),
        )

        self.assertFalse(
            self.grants.check(
                self.fields,
                self.argv,
                self.cwd,
                self.exe,
                exe_identity=(1, 2, 4, 4, 5),
            )
        )

    def test_expired_grant_does_not_match(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)
        self.now = 160.0

        self.assertFalse(
            self.grants.check(self.fields, self.argv, self.cwd, self.exe)
        )
        self.assertEqual(self.grants._grants, [])

    def test_removing_expired_grants_keeps_live_grants(self):
        expired_fields = frozenset({"notes"})
        expired_argv = ("cleanup",)
        live_argv = ("deploy", "--environment", "production")
        self.grants.add(expired_fields, expired_argv, self.cwd, self.exe, ttl=5)
        self.grants.add(self.fields, live_argv, self.cwd, self.exe, ttl=60)
        self.now = 106.0

        self.assertFalse(
            self.grants.check(
                expired_fields, expired_argv, self.cwd, self.exe
            )
        )
        self.assertEqual(
            self.grants._grants,
            [(self.fields, live_argv, self.cwd, self.exe, None, 160.0)],
        )
        self.assertTrue(
            self.grants.check(self.fields, live_argv, self.cwd, self.exe)
        )

    def test_add_waits_for_concurrent_check_to_finish(self):
        check_entered_clock = threading.Event()
        resume_check = threading.Event()
        add_entered_clock = threading.Event()
        check_result = []
        thread_errors = []

        def clock():
            thread_name = threading.current_thread().name
            if thread_name == "grant-check":
                check_entered_clock.set()
                if not resume_check.wait(timeout=2):
                    raise TimeoutError("check clock was not released")
            elif thread_name == "grant-add":
                add_entered_clock.set()
            return self.now

        grants = Grants(clock=clock)
        grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=60)
        new_argv = ("deploy", "--environment", "production")

        def check_existing_grant():
            try:
                check_result.append(
                    grants.check(self.fields, self.argv, self.cwd, self.exe)
                )
            except BaseException as exc:
                thread_errors.append(exc)

        def add_new_grant():
            try:
                grants.add(self.fields, new_argv, self.cwd, self.exe, ttl=60)
            except BaseException as exc:
                thread_errors.append(exc)

        checker = threading.Thread(
            target=check_existing_grant,
            name="grant-check",
        )
        adder = threading.Thread(
            target=add_new_grant,
            name="grant-add",
        )
        checker.start()
        try:
            self.assertTrue(check_entered_clock.wait(timeout=1))
            adder.start()
            self.assertFalse(add_entered_clock.wait(timeout=0.05))
        finally:
            resume_check.set()
            if adder.ident is not None:
                adder.join(timeout=1)
            checker.join(timeout=1)

        self.assertFalse(checker.is_alive())
        self.assertFalse(adder.is_alive())
        self.assertEqual(thread_errors, [])
        self.assertEqual(check_result, [True])
        self.assertTrue(
            grants.check(self.fields, new_argv, self.cwd, self.exe)
        )

    def test_shorter_repeat_grant_does_not_shorten_existing_grant(self):
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=120)
        self.grants.add(self.fields, self.argv, self.cwd, self.exe, ttl=10)
        self.now = 111.0

        self.assertTrue(
            self.grants.check(self.fields, self.argv, self.cwd, self.exe)
        )


if __name__ == "__main__":
    unittest.main()
