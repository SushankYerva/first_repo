# File: src/bip39_recovery.py

import os
from typing import List

from mnemonic import Mnemonic

# Path to the BIP-39 English wordlist (relative to this file)
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "../resources/bip39_english.txt")

# Load the wordlist into a Python list and set for membership tests
with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
    _WORDS = [w.strip() for w in f.readlines() if w.strip()]

WORDSET = set(_WORDS)
MNEMONIC_OBJ = Mnemonic("english")


def is_valid_mnemonic(phrase: str) -> bool:
    """
    Returns True if `phrase` is a valid BIP-39 mnemonic:
    - Word count is one of {12, 15, 18, 21, 24}
    - All words appear in the English wordlist
    - Checksum is correct per BIP-39
    """
    phrase = phrase.strip().lower()
    words = phrase.split()
    if len(words) not in {12, 15, 18, 21, 24}:
        return False
    # Every word must be in the BIP-39 English list
    for w in words:
        if w not in WORDSET:
            return False
    # Use the `mnemonic` library to check checksum
    return MNEMONIC_OBJ.check(phrase)


def recover_missing_word(words: List[str]) -> List[str]:
    """
    If exactly one word in `words` is missing or invalid, attempt to brute-force
    that position by trying all 2,048 words. Returns a list of all candidate
    complete mnemonics (as single-space–joined strings) whose checksums pass.
    If no valid checksum is found or if len(missing_indices) != 1, returns [].
    """
    # Identify positions where the word is not in the official list
    missing_indices = [i for i, w in enumerate(words) if w not in WORDSET]
    if len(missing_indices) != 1:
        return []

    idx = missing_indices[0]
    recovered_phrases = []

    for candidate in _WORDS:
        trial = list(words)  # shallow copy
        trial[idx] = candidate
        phrase = " ".join(trial)
        if MNEMONIC_OBJ.check(phrase):
            recovered_phrases.append(phrase)
            # If you only want the first match, you could break here.
            # But we collect all matches in case multiple possibilities exist.
    return recovered_phrases


def recover_single_wrong_word(words: List[str]) -> List[str]:
    """
    If exactly one of the words is “in the list” but the overall checksum fails, 
    this function brute-forces every position—for each position i, tries all 2,048 words.
    Total attempts = len(words) * 2048. Returns all candidate mnemonics whose checksums pass.
    (Only call when len(words) is 12/15/18/21/24 and all words are in the list but checksum fails.)
    """
    # Precondition: len(words) in {12,15,18,21,24} AND all(w in WORDSET for w in words)
    # but MNEMONIC_OBJ.check(" ".join(words)) is False.
    if len(words) not in {12, 15, 18, 21, 24}:
        return []
    if any(w not in WORDSET for w in words):
        return []

    recovered = []
    for i in range(len(words)):
        original = words[i]
        for candidate in _WORDS:
            if candidate == original:
                continue
            trial = list(words)
            trial[i] = candidate
            phrase = " ".join(trial)
            if MNEMONIC_OBJ.check(phrase):
                recovered.append(phrase)
        # Optionally update a progress indicator externally using i / len(words)
    return recovered
