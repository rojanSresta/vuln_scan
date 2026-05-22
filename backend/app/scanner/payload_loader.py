"""Loads attack payloads from text files."""

from __future__ import annotations

from pathlib import Path

_PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"


class PayloadLoader:
    @staticmethod
    def load(name: str) -> list[str]:
        path = _PAYLOADS_DIR / f"{name}.txt"
        if not path.is_file():
            raise FileNotFoundError(f"Payload file not found: {path}")

        values: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                values.append(stripped)
        return values

    @staticmethod
    def load_usernames() -> list[str]:
        return PayloadLoader.load("usernames")

    @staticmethod
    def load_passwords() -> list[str]:
        return PayloadLoader.load("passwords")
