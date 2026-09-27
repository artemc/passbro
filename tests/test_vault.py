import shutil
import tempfile
import unittest
from pathlib import Path

from pykeepass import PyKeePass

from passbro.vault import Ambiguous, NoSuchEntry, NoSuchField, Vault
from tests.make_fake_db import make


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tempdir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tempdir.cleanup)
        cls.password = "fake-test-database-password"
        cls.path = Path(cls._tempdir.name) / "fake.kdbx"
        make(cls.path, cls.password)

        database = PyKeePass(str(cls.path), password=cls.password)
        api_key = next(entry for entry in database.entries if entry.title == "api-key")
        api_key.notes = "FAKE-porkbun-notes"
        api_key.set_custom_property("api/secret", "FAKE-porkbun-slash-secret")
        database.save()
        cls.vault = Vault.open(cls.path, cls.password)

    def test_list_returns_paths_and_field_names_without_values(self):
        entries = self.vault.list()

        self.assertEqual(
            entries,
            [
                {
                    "path": "porkbun/api-key",
                    "fields": ["password", "username", "url", "notes", "api-secret"],
                },
                {"path": "router/admin", "fields": ["password", "username"]},
            ],
        )
        rendered = repr(entries)
        self.assertNotIn("FAKE-porkbun-key-123456", rendered)
        self.assertNotIn("FAKE-porkbun-secret-654321", rendered)
        self.assertNotIn("FAKE-porkbun-user", rendered)
        self.assertNotIn("FAKE-porkbun-notes", rendered)

    def test_list_omits_custom_fields_that_cannot_be_resolved(self):
        fields = next(
            item["fields"] for item in self.vault.list()
            if item["path"] == "porkbun/api-key"
        )

        self.assertNotIn("api/secret", fields)

    def test_resolve_standard_and_custom_fields(self):
        self.assertEqual(
            self.vault.resolve("porkbun/api-key/password"),
            "FAKE-porkbun-key-123456",
        )
        self.assertEqual(
            self.vault.resolve("porkbun/api-key/username"),
            "FAKE-porkbun-user",
        )
        self.assertEqual(
            self.vault.resolve("porkbun/api-key/url"),
            "https://FAKE.porkbun.example",
        )
        self.assertEqual(
            self.vault.resolve("porkbun/api-key/notes"),
            "FAKE-porkbun-notes",
        )
        self.assertEqual(
            self.vault.resolve("porkbun/api-key/api-secret"),
            "FAKE-porkbun-secret-654321",
        )

    def test_resolve_reference_without_slash_raises_no_such_field(self):
        with self.assertRaises(NoSuchField):
            self.vault.resolve("password")

    def test_resolve_non_string_reference_raises_no_such_field(self):
        with self.assertRaises(NoSuchField):
            self.vault.resolve(None)

    def test_resolve_missing_entry_raises_no_such_entry(self):
        marker = "FAKE-value-must-not-appear-in-error"
        with self.assertRaises(NoSuchEntry) as error:
            self.vault.resolve(f"{marker}/password")
        self.assertNotIn(marker, str(error.exception))

    def test_resolve_missing_field_raises_no_such_field(self):
        marker = "FAKE-value-must-not-appear-in-error"
        with self.assertRaises(NoSuchField) as error:
            self.vault.resolve(f"router/admin/{marker}")
        self.assertNotIn(marker, str(error.exception))

        with self.assertRaises(NoSuchField):
            self.vault.resolve("router/admin/notes")

    def test_recycle_bin_entries_are_not_listed_or_resolved(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "recycle-bin.kdbx"
            shutil.copy2(self.path, path)
            database = PyKeePass(str(path), password=self.password)
            recycled = database.add_entry(
                database.root_group,
                title="gone",
                username="FAKE-recycled-user",
                password="FAKE-recycled-password",
            )
            database.trash_entry(recycled)
            database.save()

            vault = Vault.open(path, self.password)

            self.assertNotIn(
                "Recycle Bin/gone", [item["path"] for item in vault.list()]
            )
            with self.assertRaises(NoSuchEntry):
                vault.resolve("Recycle Bin/gone/password")

    def test_resolve_duplicate_path_raises_ambiguous_without_reference_text(self):
        marker = "FAKE-ambiguous-reference-must-not-appear"
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "ambiguous.kdbx"
            shutil.copy2(self.path, path)
            database = PyKeePass(str(path), password=self.password)
            router = next(
                group for group in database.root_group.subgroups if group.name == "router"
            )
            database.add_entry(
                router,
                title="admin",
                username="FAKE-other-user",
                password="FAKE-other-password",
            )
            database.save()

            with self.assertRaises(Ambiguous) as error:
                Vault.open(path, self.password).resolve(f"router/admin/{marker}")
            self.assertNotIn(marker, str(error.exception))


if __name__ == "__main__":
    unittest.main()
