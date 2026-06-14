"""Safe file-writing and SHA-256 helpers for scan artifacts."""

import hashlib
import os
import tempfile


def sha256_text(text):
    """Return the SHA-256 digest of UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    """Return the SHA-256 digest of a file without loading it all at once."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_text(path, text, mode=0o600):
    """Write text atomically in the destination folder.

    The temporary file is flushed to disk before it replaces the destination,
    so an interrupted process does not leave a half-written client artifact.
    """
    absolute_path = os.path.abspath(path)
    folder = os.path.dirname(absolute_path)
    os.makedirs(folder, exist_ok=True)

    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".epxtool-",
        dir=folder,
        text=True,
    )
    try:
        os.chmod(temporary_path, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, absolute_path)
        os.chmod(absolute_path, mode)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def write_artifact(path, text, mode=0o600):
    """Write an artifact and a matching `.sha256` sidecar.

    Returns the hexadecimal digest.
    """
    atomic_write_text(path, text, mode=mode)
    digest = sha256_text(text)
    sidecar = digest + "  " + os.path.basename(path) + "\n"
    atomic_write_text(path + ".sha256", sidecar, mode=mode)
    return digest


def read_expected_digest(path):
    """Read a digest from `<path>.sha256`, or return an empty string."""
    sidecar_path = path + ".sha256"
    if not os.path.exists(sidecar_path):
        return ""

    with open(sidecar_path, "r", encoding="utf-8") as handle:
        first_line = handle.readline().strip()
    return first_line.split()[0] if first_line else ""


def verify_artifact(path):
    """Return `(digest, verified)`.

    `verified` is None when no sidecar exists, True when it matches, and False
    when the file no longer matches its saved digest.
    """
    actual = sha256_file(path)
    expected = read_expected_digest(path)
    if not expected:
        return actual, None
    return actual, actual == expected
