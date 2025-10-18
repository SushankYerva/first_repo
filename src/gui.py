
#Seed Phrase Validator & Recovery
#Author: Sushank Yerva
#Project: Master's final year
#ID: 24109436
#Project name: GUI based application for recovery of wallet secret keys


import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip39MnemonicValidator, Bip39Languages
)
import threading
import tkinter.ttk as ttk
import csv
import platform



# Globals / shared state

# cancel flag checked by long-running worker loops
cancel_flag = threading.Event()

# Load BIP39 English wordlist once (lowercase + stripped) for fast membership checks
with open("/home/runner/work/first_repo/first_repo/src/bip39_english.txt", "r", encoding="utf-8") as f:
    bip39_words = set(w.strip().lower() for w in f if w.strip())



# Helpers / threaded orchestration
def threaded_recover():
    cancel_flag.clear()
    t = threading.Thread(target=recover_missing_with_progress, daemon=True)
    t.start()

# progress bar
def show_progress_popup(title="Recovering Seed...", max_value=100):

    win = tk.Toplevel(root)
    win.title(title)
    win.geometry("350x140")
    win.resizable(False, False)

    label_var = tk.StringVar(value="Starting...")
    tk.Label(win, textvariable=label_var).pack(pady=10)

    bar = ttk.Progressbar(win, length=300, mode='determinate', maximum=max_value)
    bar.pack(pady=5)

    def do_cancel():
        # Set the cancellation flag; worker will stop at the next check
        cancel_flag.set()
        win.destroy()

    tk.Button(win, text="Cancel Recovery", command=do_cancel).pack(pady=5)
    return win, bar, label_var



# Live validation / highlighting (seed tab)
def update_display():

    content = text.get("1.0", tk.END).strip()
    words = content.split()

    # Clear previous tags before re-drawing
    text.tag_remove("valid", "1.0", tk.END)
    text.tag_remove("invalid", "1.0", tk.END)

    idx = "1.0"
    valid_count = 0
    for w in words:
        start = idx
        end = f"{start}+{len(w)}c"
        lw = w.lower()

        # Treat '*' and 'prefix*' as valid while composing to reduce false red flags
        ok = (
            lw in bip39_words or
            lw == "*" or
            (lw.endswith("*") and len(lw) > 1 and lw[:-1].isalpha())
        )
        tag = "valid" if ok else "invalid"
        if ok:
            valid_count += 1
        text.tag_add(tag, start, end)

        # Advance to next token (skip exactly one trailing space)
        idx = f"{end}+1c"

    word_count_label.config(text=f"Words: {len(words)} | Valid: {valid_count}")


def on_key_release(event):

    # key handler:

    if event.char in [",", ";", "\n", "\t"]:
        return "break"
    update_display()



# Seed-recovery worker (heavy work runs here on a background thread)
def recover_missing_with_progress():

    # Recover missing/partial words:
    import itertools
    from mnemonic import Mnemonic

    # --- helper: coarse address kind for gentle hinting ---
    def addr_kind(a: str) -> str:

        a = a.strip()
        if not a:
            return "unknown"
        if a.startswith(("1", "m", "n")):
            return "p2pkh"
        if a.startswith(("3", "2")):
            return "p2sh"
        if a.lower().startswith(("bc1q", "tb1q")):
            return "bech32"
        return "unknown"

    # --- Step 1: Inputs ---
    mnemo = Mnemonic("english")
    known_addr = known_address_entry.get().strip()
    seed_passphrase = seed_pp_var.get().strip()      # optional BIP-39 passphrase for seed tab
    content = text.get("1.0", tk.END).strip()
    tokens = content.split()

    # Hint early if the known address does not look like P2PKH
    if known_addr:
        knd = addr_kind(known_addr)
        if knd != "p2pkh":
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.delete("1.0", tk.END)
            seed_output_box.insert(
                tk.END,
                "⚠ The known address does not look like a legacy P2PKH address.\n"
                "This recovery currently derives P2PKH only (m/44’/.../change/index).\n\n"
            )
            seed_output_box.config(state=tk.DISABLED)

    # --- Step 2: Build suggestions per token ---
    full_list = sorted(bip39_words)
    suggestions = []
    for t in tokens:
        lw = t.lower()
        if lw == "*":
            suggestions.append(full_list)
        elif lw.endswith("*") and len(lw) > 1 and lw[:-1].isalpha():
            prefix = lw[:-1]
            cands = [w for w in bip39_words if w.startswith(prefix)]
            suggestions.append(sorted(cands) if cands else full_list)
        elif lw in bip39_words:
            suggestions.append([lw])
        else:
            suggestions.append(full_list)

    # Total combinations for determinate progress bar
    total = 1
    for s in suggestions:
        total *= len(s)

    # --- Step 3: Progress UI ---
    progress_win, progress_bar, label_var = show_progress_popup("Recovering Seed...", total)
    seed_output_box.config(state=tk.NORMAL)
    seed_output_box.delete("1.0", tk.END)
    seed_output_box.insert(tk.END, f"Candidates to test (after prefixes): {total}\n")
    if known_addr:
        seed_output_box.insert(tk.END, f"Matching against known address: {known_addr}\n")
        if seed_passphrase:
            seed_output_box.insert(tk.END, "Using BIP-39 passphrase: <set>\n")
        seed_output_box.insert(tk.END, "\n")
    seed_output_box.config(state=tk.DISABLED)

    # --- Step 4: Iterate candidates with checksum-first pruning ---
    count = 0
    found = 0
    network_choice = network_var.get()
    coin = Bip44Coins.BITCOIN_TESTNET if network_choice == "Testnet" else Bip44Coins.BITCOIN

    for combo in itertools.product(*suggestions):
        # exit cleanly if user clicked Cancel
        if cancel_flag.is_set():
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, "❌ Recovery cancelled by user.\n")
            seed_output_box.config(state=tk.DISABLED)
            break

        phrase = " ".join(combo)
        count += 1

        # Update progress bar + label
        label_var.set(f"Checking {count}/{total}")
        progress_bar["value"] = count
        progress_bar.update()

        # 4.1 Checksum gate
        if not mnemo.check(phrase):
            continue

        # 4.2 If no known address, accept any checksum-valid phrase
        if not known_addr:
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, f"{found + 1}. {phrase}\n")
            seed_output_box.config(state=tk.DISABLED)
            found += 1
            continue

        # 4.3 Derive and compare (P2PKH via BIP-44 m/44'/coin'/0'/(0|1)/i)
        try:
            seed_bytes = Bip39SeedGenerator(phrase).Generate(seed_passphrase)
            bip44_ctx = Bip44.FromSeed(seed_bytes, coin)
            acct = bip44_ctx.Purpose().Coin().Account(0)

            match = False
            for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
                ch = acct.Change(change)
                for i in range(20):  # default scan window per chain
                    addr = ch.AddressIndex(i).PublicKey().ToAddress()
                    if addr == known_addr:
                        change_path = 0 if change == Bip44Changes.CHAIN_EXT else 1
                        seed_output_box.config(state=tk.NORMAL)
                        seed_output_box.insert(
                            tk.END,
                            f"{found + 1}. {phrase}   "
                            f"[match: m/44'/{1 if network_choice == 'Testnet' else 0}'/0'/{change_path}/{i}]\n"
                        )
                        seed_output_box.config(state=tk.DISABLED)
                        found += 1
                        match = True
                        break
                if match:
                    break

            # If no match for this candidate, continue the search
            if not match:
                continue

        except Exception as e:
            # Derivation error on this candidate: log and move on
            print("Error deriving address:", e)
            continue

        # Optional guardrail: stop if we already found many matches
        if found >= 100:
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, "⚠️ Too many matches, stopping early.\n")
            seed_output_box.config(state=tk.DISABLED)
            break

    # --- Step 5: Wrap up (no matches / guidance) ---
    if found == 0:
        seed_output_box.config(state=tk.NORMAL)
        msg = "• No matching valid seed phrases found.\n"
        if known_addr:
            msg += (
                "• Check Mainnet/Testnet matches your address.\n"
                "• Current search is P2PKH only (addresses starting with 1 / m / n).\n"
                "• If you used a BIP-39 passphrase, enter it exactly (case-sensitive).\n"
            )
        seed_output_box.insert(tk.END, msg)
        seed_output_box.config(state=tk.DISABLED)

    # Clear cancel flag and close progress window
    cancel_flag.clear()
    progress_win.destroy()



# Wallet exports (CSV)
def export_wallet_addresses_csv():

    # Export visible Wallet tab paths and addresses to CSV (watch-only safe).
    # Reads the already-rendered text pane to keep output consistent with UI.

    data = wallet_output_box.get("1.0", tk.END).strip().splitlines()
    rows = []
    for line in data:
        # Expect "m/... → address" lines
        if "→" in line and line.strip().startswith("m/"):
            path, addr = map(str.strip, line.split("→"))
            rows.append((path, addr))
    if not rows:
        messagebox.showinfo("Nothing to export", "No derived addresses to export.")
        return
    filepath = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
    )
    if not filepath:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "Address"])
        writer.writerows(rows)
    messagebox.showinfo("Exported", f"Addresses saved to:\n{filepath}")


def export_wallet_secrets_csv():

    #Export gated secrets (Path, Address, WIF) to CSV.
    #Requires the 'Reveal secret keys' checkbox to be enabled and a populated cache.

    if not reveal_var.get():
        messagebox.showwarning("Secrets locked", "Enable 'Reveal secret keys' first.")
        return
    if not latest_secrets_rows:
        messagebox.showinfo("Nothing to export", "Recover first to populate secrets.")
        return
    filepath = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
    )
    if not filepath:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "Address", "WIF"])
        writer.writerows(latest_secrets_rows)
    messagebox.showinfo("Exported", f"Secrets saved to:\n{filepath}\n\n⚠ Handle this file securely.")



# GUI setup
root = tk.Tk()
root.geometry('900x680')
root.title("Seed Phrase Validator & Recovery")

if platform.system() == 'Windows':
    style = ttk.Style(root)
    style.theme_use("winnative")  # Use Windows theme
else:
    style = ttk.Style(root)
    style.theme_use("clam")
# Make selected tab visually distinct; keep others simple
style.configure("TNotebook.Tab", width='70', anchor="center")
style.map(
    "TNotebook.Tab",
    background=[("selected", "#21694f"), ("!selected", "white")],
    foreground=[("selected", "white"), ("!selected", "black")]
)

# Two-tab layout: Wallet Recovery / Seed Recovery
notebook = ttk.Notebook(root, style='TNotebook')
tab_wallet_recovery = ttk.Frame(notebook)
tab_seed_recovery = ttk.Frame(notebook)
notebook.add(tab_wallet_recovery, text='Wallet Recovery')
notebook.add(tab_seed_recovery, text='Seed Recovery')
notebook.pack(fill="both", expand=True)


# WALLET RECOVERY TAB
tk.Label(tab_wallet_recovery, text="Wallet Recovery", font=("Arial", 20)).pack(pady=(10, 5))

# Seed phrase input
tk.Label(tab_wallet_recovery, text="Enter your complete seed phrase (space-separated):").pack(pady=(0, 5))
seed_entry = scrolledtext.ScrolledText(tab_wallet_recovery, wrap=tk.WORD, height=4, font=("Arial", 12))
seed_entry.pack(pady=10, padx=20, fill=tk.X)

# Optional BIP-39 passphrase (masked by default; togglable)
pp_row = tk.Frame(tab_wallet_recovery)
pp_row.pack(padx=20, fill="x")
tk.Label(pp_row, text="BIP-39 passphrase (optional):").pack(side=tk.LEFT)
passphrase_var = tk.StringVar()
pp_entry = tk.Entry(pp_row, textvariable=passphrase_var, show="•", width=40)
pp_entry.pack(side=tk.LEFT, padx=(8, 10))
pp_show_var = tk.BooleanVar(value=False)
def toggle_pp():
    pp_entry.config(show="" if pp_show_var.get() else "•")
tk.Checkbutton(pp_row, text="Show", variable=pp_show_var, command=toggle_pp).pack(side=tk.LEFT)

# Network and scan counts
net_frame = tk.Frame(tab_wallet_recovery)
net_frame.pack(pady=8)
tk.Label(net_frame, text="Select Network: ").pack(side=tk.LEFT)
network_var_wallet = tk.StringVar(value="Mainnet")
tk.OptionMenu(net_frame, network_var_wallet, "Mainnet", "Testnet").pack(side=tk.LEFT)

tk.Label(net_frame, text="  External (0/i): ").pack(side=tk.LEFT)
num_addresses_var = tk.IntVar(value=20)
tk.Entry(net_frame, textvariable=num_addresses_var, width=5).pack(side=tk.LEFT)

tk.Label(net_frame, text="  Change (1/i): ").pack(side=tk.LEFT)
change_scan_var = tk.IntVar(value=5)
tk.Entry(net_frame, textvariable=change_scan_var, width=5).pack(side=tk.LEFT)

# Action buttons (recover + exports)
ctrl_frame = tk.Frame(tab_wallet_recovery)
ctrl_frame.pack(pady=10)

def recover_wallet():

    # Wallet derivation flow:
    # Validate mnemonic (strict BIP-39)
    # Build seed with optional passphrase
    # Derive P2PKH addresses for mainnet/testnet (BIP-44 account 0)
    # Optionally reveal xpub/xprv and WIFs when gated

    # Clear previous outputs (keep widgets in a known state)
    wallet_output_box.config(state=tk.NORMAL); wallet_output_box.delete("1.0", tk.END)
    xpub_entry.config(state=tk.NORMAL); xpub_entry.delete(0, tk.END)
    xprv_entry.config(state=tk.NORMAL); xprv_entry.delete(0, tk.END)
    wif_output_box.config(state=tk.NORMAL); wif_output_box.delete("1.0", tk.END)
    wif_output_box.config(state=tk.DISABLED)

    seed_phrase = seed_entry.get("1.0", tk.END).strip()
    words = seed_phrase.split()
    if len(words) < 12:
        wallet_output_box.insert(tk.END, "Please enter a valid 12-word or longer seed phrase.\n")
        wallet_output_box.config(state=tk.DISABLED)
        return

    # 1) Strict mnemonic validation (wordlist + count + checksum)
    try:
        Bip39MnemonicValidator(Bip39Languages.ENGLISH).Validate(seed_phrase)
    except Exception as e:
        wallet_output_box.insert(tk.END, f"Invalid BIP-39 mnemonic. {e}\n")
        wallet_output_box.config(state=tk.DISABLED)
        return

    try:
        # 2) Seed generation (passphrase="" means no passphrase)
        passphrase = passphrase_var.get()
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate(passphrase)

        # 3) BIP-44 P2PKH context (account 0)
        is_testnet = (network_var_wallet.get() == "Testnet")
        coin = Bip44Coins.BITCOIN_TESTNET if is_testnet else Bip44Coins.BITCOIN
        bip44_ctx = Bip44.FromSeed(seed_bytes, coin)

        # Derive account/chain handles once
        acct = bip44_ctx.Purpose().Coin().Account(0)
        ext_chain = acct.Change(Bip44Changes.CHAIN_EXT)
        int_chain = acct.Change(Bip44Changes.CHAIN_INT)

        # Guard against negative/empty entries
        ext_n = max(0, int(num_addresses_var.get() or 0))
        chg_n = max(0, int(change_scan_var.get() or 0))

        wallet_output_box.insert(
            tk.END,
            f"Seed Valid. Network: {'Testnet' if is_testnet else 'Mainnet'}\n"
            f"Path base: m/44'/{1 if is_testnet else 0}'/0'\n"
            f"Passphrase: {'<set>' if passphrase else '<none>'}\n\n"
            f"Showing first {ext_n} external and {chg_n} change addresses (P2PKH):\n\n"
        )

        # 4) External addresses (m/44'/coin'/0'/0/i)
        for i in range(ext_n):
            addr_ctx = ext_chain.AddressIndex(i)
            addr = addr_ctx.PublicKey().ToAddress()
            path = f"m/44'/{1 if is_testnet else 0}'/0'/0/{i}"
            wallet_output_box.insert(tk.END, f"{path} → {addr}\n")

        # 5) Change addresses (m/44'/coin'/0'/1/i)
        if chg_n:
            wallet_output_box.insert(tk.END, "\n")
        for i in range(chg_n):
            addr_ctx = int_chain.AddressIndex(i)
            addr = addr_ctx.PublicKey().ToAddress()
            path = f"m/44'/{1 if is_testnet else 0}'/0'/1/{i}"
            wallet_output_box.insert(tk.END, f"{path} → {addr}\n")

        # 6) Secrets (gated): xpub/xprv + WIF table
        latest_secrets_rows.clear()
        if reveal_var.get():
            try:
                xpub = acct.PublicKey().ToExtended()
                xprv = acct.PrivateKey().ToExtended()
                xpub_entry.insert(0, xpub)
                xprv_entry.insert(0, xprv)

                wif_output_box.config(state=tk.NORMAL)
                wif_output_box.insert(tk.END, "Path                          Address                             WIF\n")
                wif_output_box.insert(tk.END, "-"*100 + "\n")

                # External WIFs
                for i in range(ext_n):
                    idx = ext_chain.AddressIndex(i)
                    addr = idx.PublicKey().ToAddress()
                    wif = idx.PrivateKey().ToWif()
                    path = f"m/44'/{1 if is_testnet else 0}'/0'/0/{i}"
                    wif_output_box.insert(tk.END, f"{path:<28} {addr:<36} {wif}\n")
                    latest_secrets_rows.append((path, addr, wif))
                # Change WIFs
                for i in range(chg_n):
                    idx = int_chain.AddressIndex(i)
                    addr = idx.PublicKey().ToAddress()
                    wif = idx.PrivateKey().ToWif()
                    path = f"m/44'/{1 if is_testnet else 0}'/0'/1/{i}"
                    wif_output_box.insert(tk.END, f"{path:<28} {addr:<36} {wif}\n")
                    latest_secrets_rows.append((path, addr, wif))
                wif_output_box.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Secrets error", f"Failed to derive secrets: {e}")

        # Lock address box after writes (read-only view)
        wallet_output_box.config(state=tk.DISABLED)

        # Keep secrets widgets in sync with gate state
        state = tk.NORMAL if reveal_var.get() else tk.DISABLED
        xpub_entry.config(state=state)
        xprv_entry.config(state=state)
        wif_output_box.config(state=state)
        show_xprv_chk.config(state=state)
        export_secrets_btn.config(state=state)

    except Exception as e:
        wallet_output_box.insert(tk.END, f"Error: {str(e)}\n")
        wallet_output_box.config(state=tk.DISABLED)

btn_recover = tk.Button(ctrl_frame, text="Recover Wallet", command=recover_wallet)
btn_recover.pack(side=tk.LEFT, padx=10)

btn_export = tk.Button(ctrl_frame, text="Export Addresses (CSV)", command=export_wallet_addresses_csv)
btn_export.pack(side=tk.LEFT, padx=10)

export_secrets_btn = tk.Button(ctrl_frame, text="Export Secrets (CSV)", command=export_wallet_secrets_csv, state=tk.DISABLED)
export_secrets_btn.pack(side=tk.LEFT, padx=10)

# Output box (addresses). This is hidden when secrets are revealed to avoid duplication.
addr_label = tk.Label(tab_wallet_recovery, text="Recovered wallet addresses:")
addr_label.pack(pady=(12, 0))
wallet_output_box = scrolledtext.ScrolledText(tab_wallet_recovery, wrap=tk.WORD, width=80, height=5, font=("Arial", 11))
wallet_output_box.pack(padx=10, pady=5, fill="both", expand=False)
wallet_output_box.config(state=tk.DISABLED)

# Secrets gate + panel kept disabled until user opts in
secrets_gate_row = tk.Frame(tab_wallet_recovery)
secrets_gate_row.pack(fill="x", padx=10, pady=(6, 0))
reveal_var = tk.BooleanVar(value=False)

def on_reveal_toggle():

    #Toggle visibility/enabled state for secrets widgets.
    #Optionally hide the address list to prevent duplication while secrets are visible.
    state = tk.NORMAL if reveal_var.get() else tk.DISABLED
    xpub_entry.config(state=state)
    xprv_entry.config(state=state)
    wif_output_box.config(state=state)
    show_xprv_chk.config(state=state)
    export_secrets_btn.config(state=state)

    # Hide/show the address section to avoid duplication
    if reveal_var.get():
        addr_label.pack_forget()
        wallet_output_box.pack_forget()
        btn_export.config(state=tk.DISABLED)
    else:
        addr_label.pack(pady=(12, 0))
        wallet_output_box.pack(padx=10, pady=5, fill="both", expand=False)
        xprv_entry.config(show="•")
        show_xprv_var.set(False)
        btn_export.config(state=tk.NORMAL)

tk.Checkbutton(
    secrets_gate_row,
    text="I understand the risks. Reveal secret keys (xprv / WIF).",
    variable=reveal_var, command=on_reveal_toggle
).pack(anchor="w", padx=4)

secrets_frame = tk.LabelFrame(tab_wallet_recovery, text="Secrets (gated)")
secrets_frame.pack(fill="both", expand=True, padx=10, pady=(6, 10))

# xpub/xprv row (xprv masked by default, checkbox toggles it)
keys_row = tk.Frame(secrets_frame)
keys_row.pack(fill="x", padx=6, pady=6)
tk.Label(keys_row, text="Account xpub:").grid(row=0, column=0, sticky="w")
xpub_entry = tk.Entry(keys_row, font=("Courier New", 10))
xpub_entry.grid(row=0, column=1, sticky="we", padx=6, pady=2)

tk.Label(keys_row, text="Account xprv:").grid(row=1, column=0, sticky="w")
xprv_entry = tk.Entry(keys_row, font=("Courier New", 10), show="•")
xprv_entry.grid(row=1, column=1, sticky="we", padx=6, pady=2)

show_xprv_var = tk.BooleanVar(value=False)
def toggle_xprv():
    xprv_entry.config(show="" if show_xprv_var.get() else "•")
show_xprv_chk = tk.Checkbutton(keys_row, text="Show xprv", variable=show_xprv_var, command=toggle_xprv, state=tk.DISABLED)
show_xprv_chk.grid(row=1, column=2, sticky="w", padx=(8, 0))

keys_row.grid_columnconfigure(1, weight=1)

# WIF list
wif_frame = tk.Frame(secrets_frame)
wif_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
wif_output_box = scrolledtext.ScrolledText(wif_frame, wrap=tk.NONE, width=80, height=8, font=("Courier New", 10))
wif_output_box.pack(fill="both", expand=True)
wif_output_box.config(state=tk.DISABLED)

# Keep secrets widgets disabled initially (gate closed)
xpub_entry.config(state=tk.DISABLED)
xprv_entry.config(state=tk.DISABLED)
wif_output_box.config(state=tk.DISABLED)

# Cache for secrets CSV export (path, address, WIF)
latest_secrets_rows = []



# SEED RECOVERY TAB (only seed input + results are resizable)
tk.Label(tab_seed_recovery, text="Seed Recovery", font=("Arial", 20)).pack(pady=(10, 5))

# resizeable input area
input_area = tk.Frame(tab_seed_recovery)
input_area.pack(fill="both", expand=True, padx=10)
tk.Label(
    input_area,
    text="Enter your seed phrase. Use '*' for any word or 'prefix*' for a word that starts with that prefix."
).pack(anchor="w")

# Entry for candidate mnemonic with placeholder & live highlighting
text = scrolledtext.ScrolledText(input_area, wrap=tk.WORD, height=6, font=("Arial", 12))
text.pack(fill="both", expand=True, pady=(5, 0))
PLACEHOLDER = "Please enter your seed phrase here..."

# Placeholder behavior
text.insert("1.0", PLACEHOLDER)
text.config(fg="grey")
def on_focus_in(event):
    current = text.get("1.0", "end-1c")
    if current == PLACEHOLDER:
        text.delete("1.0", "end")
        text.config(fg="black")
def on_focus_out(event):
    current = text.get("1.0", "end-1c").strip()
    if not current:
        text.insert("1.0", PLACEHOLDER)
        text.config(fg="grey")
text.bind("<FocusIn>", on_focus_in)
text.bind("<FocusOut>", on_focus_out)

# Live validation hooks
text.bind("<KeyRelease>", on_key_release)
text.tag_configure("valid", foreground="darkgreen")
text.tag_configure("invalid", foreground="darkred")

# Word counter
word_count_label = tk.Label(tab_seed_recovery, text="Words: 0 | Valid: 0")
word_count_label.pack(anchor="w", padx=10, pady=(5, 0))

# Known address
address_frame = tk.Frame(tab_seed_recovery)
address_frame.pack(pady=(10, 0), fill="x", padx=10)
tk.Label(address_frame, text="Enter your known wallet address (optional):").pack(side=tk.LEFT, padx=(0, 5))
known_address_entry = tk.Entry(address_frame, width=45)
known_address_entry.pack(side=tk.LEFT, fill="x", expand=True)

# Optional BIP-39 passphrase for the seed-recovery flow (masked, togglable)
pp_frame_seed = tk.Frame(tab_seed_recovery)
pp_frame_seed.pack(pady=(8, 0), fill="x", padx=10)
tk.Label(pp_frame_seed, text="BIP-39 passphrase (optional):").pack(side=tk.LEFT)
seed_pp_var = tk.StringVar()
seed_pp_entry = tk.Entry(pp_frame_seed, textvariable=seed_pp_var, show="•")
seed_pp_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=(6, 8))
seed_pp_show_var = tk.BooleanVar(value=False)
def toggle_seed_pp():
    seed_pp_entry.config(show="" if seed_pp_show_var.get() else "•")
tk.Checkbutton(pp_frame_seed, text="Show", variable=seed_pp_show_var, command=toggle_seed_pp).pack(side=tk.LEFT)

# Controls
btn_frame = tk.Frame(tab_seed_recovery)
btn_frame.pack(pady=10, fill="x", padx=10)
tk.Label(btn_frame, text="Select Bitcoin Network:").pack(side=tk.LEFT)
network_var = tk.StringVar(value="Mainnet")
network_menu = tk.OptionMenu(btn_frame, network_var, "Mainnet", "Testnet")
network_menu.pack(side=tk.LEFT, padx=(5, 10))
tk.Button(btn_frame, text="Recover Missing Word(s)", command=threaded_recover).pack(side=tk.LEFT, padx=10)

# Export seed input to TXT
def export_seed_to_file():
    content = text.get("1.0", tk.END).strip()
    words = content.split()
    filename = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Seed Phrase")
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(" ".join(words))
        messagebox.showinfo("Exported", f"Seed phrase saved to:\n{filename}")
tk.Button(btn_frame, text="Export to File", command=export_seed_to_file).pack(side=tk.LEFT)

# resizeable output
output_area = tk.Frame(tab_seed_recovery)
output_area.pack(fill="both", expand=True, padx=10, pady=(5, 10))
tk.Label(output_area, text="Recovered Seed Phrase Combinations:").pack(anchor="w")

seed_output_box = scrolledtext.ScrolledText(output_area, wrap=tk.WORD, width=68, height=10, font=("Arial", 11))
seed_output_box.pack(fill="both", expand=True, pady=(5, 0))
seed_output_box.config(state=tk.DISABLED)

def stop_mainloop():
        root.quit()  # Ends the loop after a set time

if platform.system() == 'Linux':
    threading.Timer(15.0, stop_mainloop).start()  # Stop after 15 seconds
else:
    root.mainloop()

# Main loop (start GUI)
root.mainloop()
