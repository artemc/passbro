"""passbro broker protocol.

Each AF_UNIX stream connection carries one UTF-8 JSON object terminated by a
newline. The server returns one UTF-8 JSON object and closes the connection.

An ``ls`` request is ``{"op": "ls"}``. A ``run`` request contains ``why``,
``env`` (environment variable to KeePass reference), ``argv``, ``cwd``,
``client_env``, and an optional ``timeout`` in seconds. An omitted or null
``cwd`` uses the broker process's working directory. A relative ``cwd`` is
invalid; the accepted working directory is normalized with ``realpath`` and
is shared by executable lookup, approval, grants, audit, and command
execution. Omitted ``client_env`` is an empty mapping. ``timeout`` defaults
to 600 seconds and
must be between 0 and 600 seconds, inclusive. Each request line, including its
newline, is limited to 1 MiB. Secret values are never part of a request.

Successful ``ls`` replies contain entry paths and field names only. Successful
``run`` replies contain a decision (``once`` for this request, ``hour`` for an
hour grant, including a repeated request served by that grant, or ``auto`` for
automatic approval), command exit status, base64 stdout and stderr, and a
truncation flag. This broker currently returns ``once`` or ``hour``. Each
output stream is limited to 1 MiB after secret masking. A timed-out command
returns a ``timeout`` error without stdout or stderr. Errors contain one of
``denied``, ``timeout``, ``no_such_field``, ``executable_not_found``,
``executable_changed``, ``bad_request``, or ``internal_error``, with a safe
message that does not echo request values. ``executable_not_found`` is
returned before a question when ``argv[0]`` cannot be resolved to an
executable using the client's ``PATH`` (or ``os.defpath`` when absent) or the
request working directory.
``executable_changed`` is returned without starting the command if the
resolved executable's device, inode, size, modification time, or change time
differs from the snapshot taken before the owner was asked.
"""
