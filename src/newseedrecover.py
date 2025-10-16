#!/usr/bin/env python3
"""
Seed Phrase Recovery Tool

This script takes:
  1. An incomplete BIP-39 seed phrase (12 or 24 words) in which missing words are
     represented by an underscore "_" (one underscore per missing word).
  2. The first Bitcoin address corresponding to the complete seed phrase.

It then brute-forces all possible replacements for the missing words (using the
standard 2048-word English BIP-39 wordlist), checks each candidate phrase’s checksum,
derives the “first address” (m/44'/0'/0'/0/0 for P2PKH, or the appropriate path for
P2SH-SegWit / Bech32 depending on address format), and finally prints out the complete
seed phrase that produces the matching first address.

Dependencies (install via pip if not already present):
    pip install mnemonic bip_utils

Usage:
    1. Run this script.
    2. When prompted, paste your incomplete phrase, using "_" (underscore) for each
       missing word. For example:
         abandon abandon abandon _ abandon abandon abandon abandon abandon abandon abandon about
       (Here, the 4th word is missing.)
    3. When prompted, paste the first address you know (e.g., "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").
    4. The script will attempt to fill in the blanks and print the complete phrase.

Note:
    - If more than 2 words are missing, brute-forcing may be very slow (2,048³ ≈ 8.6×10^9 candidates).
      In that case, consider supplying partial spellings or reducing the search space.
    - This code automatically detects whether the given address is legacy (P2PKH: starts with '1'),
      P2SH-SegWit (starts with '3'), or native SegWit (Bech32: starts with 'bc1') and derives
      accordingly.
"""

import os
import itertools
from mnemonic import Mnemonic
from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)


def detect_bip44_coin(address: str):
    """
    Detect which Bip44Coins to use based on the address prefix.
    - P2PKH (legacy) addresses start with '1'   -> Bip44Coins.BITCOIN
    - P2SH-SegWit addresses start with '3'      -> Bip44Coins.BITCOIN_P2SH_SEGWIT
    - Native SegWit addresses start with 'bc1' -> Bip44Coins.BITCOIN_SEGWIT
    Default: assume legacy P2PKH.
    """
    addr = address.strip().lower()
    if addr.startswith("1"):
        return Bip44Coins.BITCOIN
    elif addr.startswith("3"):
        return Bip44Coins.BITCOIN_P2SH_SEGWIT
    elif addr.startswith("bc1"):
        return Bip44Coins.BITCOIN_SEGWIT
    else:
        # Unknown format, default to legacy
        return Bip44Coins.BITCOIN


def derive_first_address_from_seed(seed_bytes: bytes, coin: Bip44Coins) -> str:
    """
    Given a 64-byte BIP-39 seed and a Bip44Coins enum, derive the first address:
    Path = m/44'/coin_type'/0'/0/0  (account = 0, external chain, index = 0)
    """
    bip44_ctx = Bip44.FromSeed(seed_bytes, coin)
    account0 = bip44_ctx.Purpose().Coin().Account(0)
    first_addr_node = account0.Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    return first_addr_node.PublicKey().ToAddress()


def recover_seed_phrase(incomplete_phrase: str, target_address: str):
    """
    Attempt to recover a complete seed phrase by filling in underscores ("_") with
    words from the BIP-39 English wordlist, such that the derived first address matches
    the provided target_address.

    Returns:
        The recovered complete phrase as a string if found; otherwise, None.
    """
    mnemo = Mnemonic("english")
    wordlist = mnemo.wordlist  # 2,048 English words

    # Normalize and split the input into words
    parts = [w.strip() for w in incomplete_phrase.strip().split()]
    num_words = len(parts)
    if num_words not in (12, 24):
        print(f"Error: Expected 12 or 24 words (including underscores), got {num_words}.")
        return None

    # Identify missing indices (where the user put "_")
    missing_indices = [idx for idx, w in enumerate(parts) if w == "_"]
    k = len(missing_indices)

    if k == 0:
        # No missing words: just check the phrase directly
        candidate = " ".join(parts)
        if mnemo.check(candidate):
            # Derive first address and compare
            seed = Bip39SeedGenerator(candidate).Generate()
            coin = detect_bip44_coin(target_address)
            derived_addr = derive_first_address_from_seed(seed, coin)
            if derived_addr == target_address:
                return candidate
            else:
                print("The provided full phrase is valid BIP-39 but does NOT match the given address.")
                return None
        else:
            print("The provided full phrase is NOT a valid BIP-39 mnemonic.")
            return None

    if k > 2:
        print(f"Warning: {k} missing words → brute-forcing 2,048^{k} possibilities!")
        print("This may take a VERY long time. Consider supplying partial spellings or reducing missing words.")
        # You can choose to continue or abort here:
        # return None

    print(f"Found {k} missing word slot(s). Brute-forcing...")

    # Pre-calculate combinations of candidate words
    total_combinations = len(wordlist) ** k
    print(f"Total candidates to check: {total_combinations:,}")

    # Determine which Bip44Coins to use
    coin = detect_bip44_coin(target_address)

    # Iterate over all possible word tuples for the missing slots
    for combo_idx, candidate_words in enumerate(itertools.product(wordlist, repeat=k), start=1):
        # Fill in the missing slots
        temp = parts.copy()
        for pos, w in zip(missing_indices, candidate_words):
            temp[pos] = w
        candidate_phrase = " ".join(temp)

        # 1) Check BIP-39 checksum validity
        if not mnemo.check(candidate_phrase):
            continue

        # 2) Derive seed and the first address
        seed_bytes = Bip39SeedGenerator(candidate_phrase).Generate()
        derived_address = derive_first_address_from_seed(seed_bytes, coin)

        # 3) Check if it matches the target
        if derived_address == target_address:
            print(f"\nMatch found after checking {combo_idx:,} candidates!")
            return candidate_phrase

        # Optional: print progress every N iterations
        if combo_idx % 100_000 == 0:
            print(f"  Checked {combo_idx:,} / {total_combinations:,} candidates...")

    # If we exit the loop, no match was found
    print("No matching phrase found.")
    return None


if __name__ == "__main__":
    print("=== BIP-39 Missing-Word Recovery ===")
    print("Enter your incomplete seed phrase, using an underscore (_) for each missing word.")
    print("Example (12 words, missing 4th and 8th):")
    print("  abandon abandon abandon _ abandon abandon abandon _ abandon abandon abandon about")
    print("-----------------------------------------------------------")
    incomplete = input("Incomplete phrase: ").strip()

    target_addr = input("First address (e.g. 1..., 3..., or bc1...): ").strip()
    print("\nAttempting recovery...")
    recovered = recover_seed_phrase(incomplete, target_addr)

    if recovered:
        print("\n=== Recovery Successful! ===")
        print("Complete seed phrase:")
        print(recovered)
    else:
        print("\n=== Recovery Failed ===")
        print("Could not find a phrase matching the given address.")
