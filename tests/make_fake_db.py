import argparse
from getpass import getpass
from pathlib import Path

from pykeepass import create_database


def make(path, password):
    """Create a KeePass database populated only with fake test values."""
    if Path(path).exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")

    database = create_database(path, password=password)
    porkbun = database.add_group(database.root_group, "porkbun")
    router = database.add_group(database.root_group, "router")

    porkbun_entry = database.add_entry(
        porkbun,
        title="api-key",
        username="FAKE-porkbun-user",
        password="FAKE-porkbun-key-123456",
        url="https://FAKE.porkbun.example",
    )
    porkbun_entry.set_custom_property("api-secret", "FAKE-porkbun-secret-654321")

    database.add_entry(
        router,
        title="admin",
        username="FAKE-router-user",
        password="abc",
    )
    database.save()
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create a fake passbro KeePass database.")
    parser.add_argument("path", type=Path, help="path for the new .kdbx database")
    args = parser.parse_args(argv)
    path = args.path.expanduser()

    if path.exists():
        parser.error(f"refusing to overwrite existing file: {path}")

    password = getpass("KeePass database password: ")
    try:
        make(path, password)
    except FileExistsError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
