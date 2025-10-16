# File: src/utils.py

from typing import List


def normalize_mnemonic_input(raw: str) -> List[str]:
    """
    Normalize a user’s raw input string into a list of lowercase words, stripping any
    extra whitespace. Splits on whitespace. Everything is lowercased.
    """
    return [w.strip().lower() for w in raw.strip().split() if w.strip()]


def words_to_phrase(words: List[str]) -> str:
    """
    Join a list of words into a single-space–separated mnemonic phrase.
    """
    return " ".join(words)
