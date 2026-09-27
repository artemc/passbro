"""Read and resolve entries in a KeePass database."""

from pathlib import Path

from pykeepass import PyKeePass


class NoSuchEntry(LookupError):
    """The requested entry path does not exist."""


class NoSuchField(LookupError):
    """The requested field does not exist or has no value."""


class Ambiguous(LookupError):
    """More than one entry has the requested path."""


_STANDARD_FIELDS = ("password", "username", "url", "notes")


def _entry_path(entry):
    parts = entry.path
    if not parts or any(part is None for part in parts):
        return None
    return "/".join(parts)


def _entry_fields(entry):
    fields = [
        name
        for name in _STANDARD_FIELDS
        if getattr(entry, name) is not None
    ]
    fields.extend(
        name
        for name, value in entry.custom_properties.items()
        if value is not None and "/" not in name
    )
    return fields


def _in_recyclebin(entry, database):
    recyclebin = database.recyclebin_group
    if recyclebin is None:
        return False

    recyclebin_uuid = recyclebin.uuid
    group = entry.parentgroup
    while group is not None:
        if group.uuid == recyclebin_uuid:
            return True
        group = group.parentgroup
    return False


class Vault:
    """An open KeePass database with safe listing and explicit resolution."""

    def __init__(self, database):
        self._database = database

    @classmethod
    def open(cls, path, password):
        """Open the database at path using password."""
        database = PyKeePass(str(Path(path)), password=password)
        return cls(database)

    def list(self):
        """Return entry paths and field names without disclosing values."""
        entries = []
        for entry in self._database.entries:
            path = _entry_path(entry)
            if path is not None and not _in_recyclebin(entry, self._database):
                entries.append({"path": path, "fields": _entry_fields(entry)})
        return entries

    def resolve(self, ref):
        """Return a field value for a ``entry/path/field`` reference."""
        if not isinstance(ref, str) or "/" not in ref:
            raise NoSuchField("reference must include an entry path and field")

        entry_path, field = ref.rsplit("/", 1)
        if not entry_path:
            raise NoSuchEntry("reference does not include an entry path")
        if not field:
            raise NoSuchField("reference does not include a field")

        matches = [
            entry
            for entry in self._database.entries
            if _entry_path(entry) == entry_path
            and not _in_recyclebin(entry, self._database)
        ]
        if not matches:
            raise NoSuchEntry("entry does not exist")
        if len(matches) > 1:
            raise Ambiguous("entry path is not unique")

        entry = matches[0]
        if field in _STANDARD_FIELDS:
            value = getattr(entry, field)
        else:
            value = entry.custom_properties.get(field)

        if value is None:
            raise NoSuchField("field does not exist or has no value")
        return value
