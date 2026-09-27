import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from pykeepass import PyKeePass

from tests.make_fake_db import main, make


class MakeFakeDatabaseTests(unittest.TestCase):
    def test_database_is_created_and_opens(self):
        password = "fake-test-database-password"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake.kdbx"

            result = make(path, password)

            self.assertEqual(result, path)
            self.assertTrue(path.is_file())
            database = PyKeePass(str(path), password=password)
            self.assertEqual(
                {group.name for group in database.root_group.subgroups},
                {"porkbun", "router"},
            )
            porkbun_entry = database.find_entries(path=["porkbun", "api-key"])
            router_entry = database.find_entries(path=["router", "admin"])
            self.assertEqual(porkbun_entry.password, "FAKE-porkbun-key-123456")
            self.assertEqual(porkbun_entry.url, "https://FAKE.porkbun.example")
            api_secret = porkbun_entry.get_custom_property("api-secret")
            self.assertEqual(api_secret, "FAKE-porkbun-secret-654321")
            self.assertNotIn(porkbun_entry.url, api_secret)
            self.assertNotIn(api_secret, porkbun_entry.url)
            self.assertEqual(router_entry.password, "abc")

    def test_command_line_creates_database_at_expanded_path(self):
        password = "fake-test-database-password"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake.kdbx"

            with patch("tests.make_fake_db.getpass", return_value=password):
                self.assertEqual(main([str(path)]), 0)

            database = PyKeePass(str(path), password=password)
            self.assertIsNotNone(database.find_entries(path=["porkbun", "api-key"]))

    def test_command_line_refuses_to_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "already-exists.kdbx"
            original_content = b"keep this file"
            path.write_bytes(original_content)

            with patch("tests.make_fake_db.getpass") as prompt:
                with self.assertRaises(SystemExit) as error:
                    main([str(path)])

            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_bytes(), original_content)
            prompt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
