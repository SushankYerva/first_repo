# File: src/key_derivation.py

import re
from typing import Dict, List

from bip_utils import (
    Bip39SeedGenerator,
    Bip32Slip10Secp256k1,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Given a BIP-39 mnemonic (12–24 words) and optional passphrase,
    return the 64-byte seed (binary) as per BIP-39.
    """
    # bip_utils: Bip39SeedGenerator generates the seed bytes directly.
    return Bip39SeedGenerator(mnemonic).Generate(passphrase)


def derive_from_path(seed_bytes: bytes, derivation_path: str, coin: str) -> Dict[str, str]:
    """
    Perform a generic BIP-32 derivation from `seed_bytes` following `derivation_path`.
    - `derivation_path` must be a string like "m/44'/0'/0'/0/0".
    - `coin` must be either "bitcoin" or "zcash" (case-insensitive).
    Returns a dict with keys:
      {
        "private_key_wif": <str>,
        "public_key_hex": <str>,
        "address": <str>
      }
    """
    # Validate derivation_path format: must start with "m/" and contain only digits, apostrophes, and slashes
    if not re.fullmatch(r"m(/[0-9]+'?)+", derivation_path):
        raise ValueError(f"Invalid derivation path: {derivation_path}")

    coin_lower = coin.strip().lower()
    # First, derive a root node from seed
    root = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    # Strip the leading "m/" and feed the rest into DerivePath
    path_without_m = derivation_path[2:]  # e.g., "44'/0'/0'/0/0"
    child = root.DerivePath(path_without_m)

    priv_wif = child.PrivateKey().ToWif()
    pub_hex = child.PublicKey().RawCompressed().ToHex()

    # Now compute the address based on coin
    if coin_lower == "bitcoin":
        # For Bitcoin, the library’s ToAddress() returns a P2PKH Base58Check by default
        address = child.PublicKey().ToAddress()
    elif coin_lower == "zcash":
        # For Zcash (transparent t-address), ToAddress() with Bip44Coins.ZCASH would be used.
        # But here we used generic BIP-32. The ToAddress() method still picks up
        # the correct version bytes if the chain-code/coin-type were originally Zcash.
        # However, since we derived via Slip10, ToAddress() might default to Bitcoin parameters.
        # A safer approach is: re-derive using Bip44 if you specifically want Zcash.
        # We'll do this fallback: if path starts with "m/44'/133'", use Bip44.
        if derivation_path.startswith("m/44'/133'"):
            # Re-derive specifically with Bip44 for Zcash
            bip44 = Bip44.FromSeed(seed_bytes, Bip44Coins.ZCASH)
            # Re-derive each level from the path segments
            # Path: m / 44' / 133' / account' / change / index
            segments = derivation_path.split("/")[1:]  # ["44'", "133'", "0'", "0", "0"]
            # Purpose() and Coin() are implicit in Bip44.FromSeed
            account_idx = int(segments[2].rstrip("'"))
            change_idx = int(segments[3])
            addr_idx = int(segments[4])
            acct = bip44.Purpose().Coin().Account(account_idx)
            chain = acct.Change(Bip44Changes.CHAIN_EXT if change_idx == 0 else Bip44Changes.CHAIN_INT)
            addr_obj = chain.AddressIndex(addr_idx)
            priv_wif = addr_obj.PrivateKey().ToWif()
            pub_hex = addr_obj.PublicKey().RawCompressed().ToHex()
            address = addr_obj.PublicKey().ToAddress()
        else:
            # If not using BIP-44 convention, we fallback to raw child.PublicKey().ToAddress()
            address = child.PublicKey().ToAddress()
    else:
        raise ValueError(f"Coin '{coin}' not supported. Only 'bitcoin' or 'zcash' are allowed.")

    return {
        "private_key_wif": priv_wif,
        "public_key_hex": pub_hex,
        "address": address,
    }


def derive_bip44_address(
    seed_bytes: bytes,
    coin: str,
    account: int = 0,
    change: int = 0,
    address_index: int = 0,
) -> Dict[str, str]:
    """
    Derive a BIP-44 address using a higher-level interface:
    - `coin` must be "bitcoin" or "zcash"
    - `account`, `change`, `address_index` are integers
    Returns a dict with keys: private_key_wif, public_key_hex, address
    """
    coin_lower = coin.strip().lower()

    if coin_lower == "bitcoin":
        coin_enum = Bip44Coins.BITCOIN
    elif coin_lower == "zcash":
        coin_enum = Bip44Coins.ZCASH
    else:
        raise ValueError(f"Coin '{coin}' not supported for BIP-44 derivation.")

    bip44 = Bip44.FromSeed(seed_bytes, coin_enum)
    acct = bip44.Purpose().Coin().Account(account)
    chain = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
    addr_obj = chain.AddressIndex(address_index)

    return {
        "private_key_wif": addr_obj.PrivateKey().ToWif(),
        "public_key_hex": addr_obj.PublicKey().RawCompressed().ToHex(),
        "address": addr_obj.PublicKey().ToAddress(),
    }


def derive_multiple_indices(
    seed_bytes: bytes,
    coin: str,
    base_path: str,
    count: int = 5,
) -> List[Dict[str, str]]:
    """
    Given:
      - `seed_bytes`: 64-byte BIP-39 seed,
      - `coin`: "bitcoin" or "zcash",
      - `base_path`: string like "m/44'/0'/0'/0" (without the final index),
      - `count`: number of consecutive indices to derive,
    Returns a list of dicts, each with:
      {
        "derivation_path": <str>,
        "private_key_wif": <str>,
        "public_key_hex": <str>,
        "address": <str>
      }
    """
    results = []
    for i in range(count):
        full_path = f"{base_path}/{i}"
        info = derive_from_path(seed_bytes, full_path, coin)
        info["derivation_path"] = full_path
        results.append(info)
    return results
