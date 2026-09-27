import json
import os
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from passbro.audit import Audit


class AuditTests(unittest.TestCase):
    def test_write_appends_json_lines_with_local_iso_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "audit.jsonl"
            audit = Audit(path)

            audit.write(event="grant", fields=["password", "url"], decision="once")
            audit.write(event="deny", fields=["username"])

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            first, second = (json.loads(line) for line in lines)
            self.assertEqual(first["event"], "grant")
            self.assertEqual(first["fields"], ["password", "url"])
            self.assertEqual(first["decision"], "once")
            self.assertEqual(second["event"], "deny")
            self.assertEqual(second["fields"], ["username"])
            parsed_timestamp = datetime.fromisoformat(first["ts"])
            self.assertIsNotNone(parsed_timestamp.utcoffset())

    def test_metadata_is_preserved_and_caller_timestamp_is_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            Audit(path).write(
                event="grant",
                env={"PORKBUN_API_KEY": "porkbun/api-key/password"},
                client_env={"PGPASS": "router/admin/password"},
                fields=["password", "username", "url", "api-secret"],
                argv=["./renew.sh", "--profile", "production"],
                secrets=["porkbun/api-key/password"],
                short_values=["router/admin/password"],
                decision="once",
                ts="caller timestamp",
            )

            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["event"], "grant")
            self.assertEqual(record["env"], {"PORKBUN_API_KEY": "porkbun/api-key/password"})
            self.assertEqual(record["client_env"], {"PGPASS": "router/admin/password"})
            self.assertEqual(record["fields"], ["password", "username", "url", "api-secret"])
            self.assertEqual(record["argv"], ["./renew.sh", "--profile", "production"])
            self.assertEqual(record["secrets"], ["porkbun/api-key/password"])
            self.assertEqual(record["short_values"], ["router/admin/password"])
            self.assertEqual(record["decision"], "once")
            self.assertNotEqual(record["ts"], "caller timestamp")
            self.assertIsNotNone(datetime.fromisoformat(record["ts"]).utcoffset())

    def test_file_and_created_directory_have_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory) / "passbro"
            path = log_dir / "audit.jsonl"
            Audit(path).write(event="grant")

            self.assertEqual(stat.S_IMODE(log_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_directory_permissions_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o750)
            path = Path(directory) / "audit.jsonl"

            Audit(path).write(event="grant")

            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o750)

    def test_existing_file_permissions_are_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text("old record\n", encoding="utf-8")
            os.chmod(path, 0o644)

            Audit(path).write(event="grant")

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
