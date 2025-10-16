from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

mnemonic = (
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
    "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
)

# 1) Verify checksum
mnemo = Mnemonic("english")
assert mnemo.check(mnemonic), "❌ Checksum failed!"

# 2) Generate the binary seed
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# 3) Derive the first Testnet P2PKH address at m/44'/1'/0'/0/0
ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_TESTNET)
addr = (
    ctx
    .Purpose()        # m/44'
    .Coin()           # m/44'/1'
    .Account(0)       # m/44'/1'/0'
    .Change(Bip44Changes.CHAIN_EXT)  # m/44'/1'/0'/0'
    .AddressIndex(0)  # m/44'/1'/0'/0/0
    .PublicKey()
    .ToAddress()
)

print("First Testnet address:", addr)
