"""Byte-level masking for secret values in output streams."""


_MASK = "[hidden]".encode("utf-8")
MIN_SECRET_LENGTH = 4


def mask(data: bytes, secrets: list[str]) -> bytes:
    """Replace occurrences of secrets with a fixed UTF-8 marker.

    Values shorter than MIN_SECRET_LENGTH Unicode code points are ignored.
    Matching is byte-based, and overlapping matches are merged before the
    original data is rebuilt in one pass.
    """
    intervals = []
    for secret in secrets:
        if len(secret) < MIN_SECRET_LENGTH:
            continue

        encoded_secret = secret.encode("utf-8")
        start = 0
        while True:
            start = data.find(encoded_secret, start)
            if start == -1:
                break
            intervals.append((start, start + len(encoded_secret)))
            start += 1

    if not intervals:
        return data

    intervals.sort()
    merged = []
    for start, end in intervals:
        if merged and start < merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))

    parts = []
    cursor = 0
    for start, end in merged:
        parts.extend((data[cursor:start], _MASK))
        cursor = end
    parts.append(data[cursor:])
    return b"".join(parts)
