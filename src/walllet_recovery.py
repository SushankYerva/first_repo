import tkinter as tk
from tkinter import ttk, filedialog
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import csv


def recover_wallet():
    seed_phrase = seed_entry.get("1.0", tk.END).strip()
    words = seed_phrase.split()
    output_box.config(state=tk.NORMAL)
    output_box.delete("1.0", tk.END)

    if len(words) < 12:
        output_box.insert(tk.END, "❌ Please enter a valid 12-word or longer seed phrase.\n")
        return

    try:
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
        coin = Bip44Coins.BITCOIN_TESTNET if network_var.get() == "Testnet" else Bip44Coins.BITCOIN
        bip44_ctx = Bip44.FromSeed(seed_bytes, coin)

        count = num_addresses_var.get()
        output_box.insert(tk.END, f"Seed Valid. Showing first {count} addresses (P2PKH):\n\n")

        for i in range(count):
            addr_ctx = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
            addr = addr_ctx.PublicKey().ToAddress()
            path = f"m/44'/{1 if network_var.get() == 'Testnet' else 0}'/0'/0/{i}"
            output_box.insert(tk.END, f"{path} → {addr}\n")

    except Exception as e:
        output_box.insert(tk.END, f"❌ Error: {str(e)}\n")

    output_box.config(state=tk.DISABLED)

# ==== EXPORT ====
def export_to_csv():
    data = output_box.get("1.0", tk.END).strip().splitlines()
    if not data or "→" not in data[0]:
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not filepath:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "Address"])
        for line in data:
            if "→" in line:
                path, addr = map(str.strip, line.split("→"))
                writer.writerow([path, addr])
