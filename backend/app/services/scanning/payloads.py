"""Load scan payloads and credential lists from text files."""

from __future__ import annotations

from pathlib import Path

_PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"


def _load_lines(filename: str) -> list[str]:
    path = _PAYLOADS_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Payload file not found: {path}")

    values: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            values.append(stripped)
    return values


def load_payloads(name: str) -> list[str]:
    return _load_lines(f"{name}.txt")


def load_usernames() -> list[str]:
    return _load_lines("usernames.txt")


def load_passwords() -> list[str]:
    return _load_lines("passwords.txt")
