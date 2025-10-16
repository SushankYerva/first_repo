import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39MnemonicValidator, Bip39Languages
import threading
import tkinter.ttk as ttk
import csv


cancel_flag = threading.Event()

# Load BIP39 English wordlist (lower-case)
with open("bip39_english.txt", "r") as f:
    bip39_words = set(w.strip().lower() for w in f.read().splitlines())

def threaded_recover():
    cancel_flag.clear()
    thread = threading.Thread(target=recover_missing_with_progress)
    thread.start()


def show_progress_popup(title="Recovering Seed...", max_value=100):
    progress_win = tk.Toplevel(root)
    progress_win.title(title)
    progress_win.geometry("350x140")
    progress_win.resizable(False, False)

    label_var = tk.StringVar()
    label_var.set("Starting...")

    tk.Label(progress_win, textvariable=label_var).pack(pady=10)
    progress = ttk.Progressbar(progress_win, length=300, mode='determinate', maximum=max_value)
    progress.pack(pady=5)

    def cancel():
        cancel_flag.set()
        progress_win.destroy()

    cancel_button = tk.Button(progress_win, text="Cancel Recovery", command=cancel)
    cancel_button.pack(pady=5)

    return progress_win, progress, label_var


def update_display():
    content = text.get("1.0", tk.END).strip()
    words = content.split()

    text.tag_remove("valid", "1.0", tk.END)
    text.tag_remove("invalid", "1.0", tk.END)

    # Re-tag (foreground only)
    idx = "1.0"
    valid_count = 0
    for w in words:
        start = idx
        end = f"{start}+{len(w)}c"
        lw = w.lower()
        tag = "valid" if (lw in bip39_words or lw == '*') else "invalid"
        if tag == "valid":
            valid_count += 1
        text.tag_add(tag, start, end)
        idx = f"{end}+1c"  # skip the space

    word_count_label.config(text=f"Words: {len(words)} | Valid: {valid_count}")

def on_key_release(event):
    # Disallow delimiters
    if event.char in [",", ";", "\n", "\t"]:
        return "break"
    update_display()


def recover_missing_with_progress():
    import itertools
    from mnemonic import Mnemonic
    from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

    # --- helpers ---
    def addr_kind(a: str):
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

    # Step 1: Inputs
    mnemo = Mnemonic("english")
    known_addr = known_address_entry.get().strip()
    seed_passphrase = seed_pp_var.get().strip()      # <- optional passphrase (seed tab)
    content = text.get("1.0", tk.END).strip()
    words = content.split()

    # Step 1.1: quick hint if the known address isn't P2PKH
    if known_addr:
        kind = addr_kind(known_addr)
        if kind != "p2pkh":
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.delete("1.0", tk.END)
            seed_output_box.insert(tk.END,
                "⚠ The known address looks like "
                f"{'P2SH (3/2...)' if kind=='p2sh' else 'Bech32 (bc1/tb1...)' if kind=='bech32' else 'a non-P2PKH type'}.\n"
                "This recovery currently derives P2PKH only (m/44’/.../0/i). "
                "Switch the address type/derivation in your wallet tab if needed.\n\n"
            )
            seed_output_box.config(state=tk.DISABLED)
            # continue anyway, but user is now warned

    # Step 2: Build suggestions per token
    # Rules:
    #   "*"                -> all words
    #   "prefix*"          -> all BIP39 words starting with prefix
    #   exact valid word   -> fixed
    #   anything else      -> all words (fallback)
    suggestions = []
    for w in words:
        lw = w.lower()
        if lw == "*":
            suggestions.append(sorted(bip39_words))
        elif lw.endswith("*") and len(lw) > 1 and lw[:-1].isalpha():
            prefix = lw[:-1]
            cands = [bw for bw in bip39_words if bw.startswith(prefix)]
            suggestions.append(sorted(cands) if cands else sorted(bip39_words))
        elif lw in bip39_words:
            suggestions.append([lw])
        else:
            suggestions.append(sorted(bip39_words))

    total_combinations = 1
    for s in suggestions:
        total_combinations *= len(s)

    # Step 3: Progress UI
    progress_win, progress_bar, label_var = show_progress_popup("Recovering Seed...", total_combinations)
    seed_output_box.config(state=tk.NORMAL)
    seed_output_box.delete("1.0", tk.END)
    seed_output_box.insert(tk.END, f"Candidates to test (after prefixes): {total_combinations}\n")
    if known_addr:
        seed_output_box.insert(tk.END, f"Matching against known address: {known_addr}\n")
        if seed_passphrase:
            seed_output_box.insert(tk.END, "Using BIP-39 passphrase: <set>\n")
        seed_output_box.insert(tk.END, "\n")
    seed_output_box.config(state=tk.DISABLED)

    combinations = itertools.product(*suggestions)
    count = 0
    found = 0

    # Step 4: Iterate candidates
    for combo in combinations:
        if cancel_flag.is_set():
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, "❌ Recovery cancelled by user.\n")
            seed_output_box.config(state=tk.DISABLED)
            break

        phrase = " ".join(combo)
        count += 1

        # Update progress
        label_var.set(f"Checking {count}/{total_combinations}")
        progress_bar["value"] = count
        progress_bar.update()

        # BIP-39 checksum
        if not mnemo.check(phrase):
            continue

        # If no address provided, list all checksum-valid phrases
        if not known_addr:
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, f"{found + 1}. {phrase}\n")
            seed_output_box.config(state=tk.DISABLED)
            found += 1
            continue

        # Address match using passphrase + P2PKH (m/44'/coin'/0'/change/index)
        try:
            seed_bytes = Bip39SeedGenerator(phrase).Generate(seed_passphrase)
            network_choice = network_var.get()
            coin = Bip44Coins.BITCOIN_TESTNET if network_choice == "Testnet" else Bip44Coins.BITCOIN
            bip44_ctx = Bip44.FromSeed(seed_bytes, coin)

            match_found = False
            for change in [Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT]:
                change_ctx = bip44_ctx.Purpose().Coin().Account(0).Change(change)

                for index in range(20):  # First 20 addrs per chain
                    addr_ctx = change_ctx.AddressIndex(index)
                    derived_addr = addr_ctx.PublicKey().ToAddress()

                    if derived_addr == known_addr:
                        change_path = 0 if change == Bip44Changes.CHAIN_EXT else 1  # <-- FIXED
                        seed_output_box.config(state=tk.NORMAL)
                        seed_output_box.insert(
                            tk.END,
                            f"{found + 1}. {phrase}   "
                            f"[match: m/44'/{1 if network_choice == 'Testnet' else 0}'/0'/{change_path}/{index}]\n"
                        )
                        seed_output_box.config(state=tk.DISABLED)
                        found += 1
                        match_found = True
                        break
                if match_found:
                    break

            if not match_found:
                continue

        except Exception as e:
            # Show once in console, skip candidate
            print("Error deriving address:", e)
            continue

        if found >= 100:
            seed_output_box.config(state=tk.NORMAL)
            seed_output_box.insert(tk.END, "⚠️ Too many matches, stopping early.\n")
            seed_output_box.config(state=tk.DISABLED)
            break

    # Step 5: Wrap up
    if found == 0:
        seed_output_box.config(state=tk.NORMAL)
        msg = "❌ No matching valid seed phrases found.\n"
        if known_addr:
            msg += (
                "• Check that the network (Mainnet/Testnet) matches your address.\n"
                "• This tool currently checks P2PKH only (addresses starting with 1 / m / n).\n"
                "• If your address starts with 3/2 (P2SH) or bc1/tb1 (SegWit), switch derivation accordingly.\n"
                "• If you used a BIP-39 passphrase, enter it exactly (case-sensitive).\n"
            )
        seed_output_box.insert(tk.END, msg)
        seed_output_box.config(state=tk.DISABLED)

    cancel_flag.clear()
    progress_win.destroy()



def export_wallet_addresses_csv():
    data = wallet_output_box.get("1.0", tk.END).strip().splitlines()
    rows = []
    for line in data:
        if "→" in line and line.strip().startswith("m/"):
            path, addr = map(str.strip, line.split("→"))
            rows.append((path, addr))
    if not rows:
        messagebox.showinfo("Nothing to export", "No derived addresses to export.")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not filepath:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "Address"])
        writer.writerows(rows)
    messagebox.showinfo("Exported", f"Addresses saved to:\n{filepath}")


def export_wallet_secrets_csv():
    if not reveal_var.get():
        messagebox.showwarning("Secrets locked", "Enable 'Reveal secret keys' first.")
        return
    if not latest_secrets_rows:
        messagebox.showinfo("Nothing to export", "Recover first to populate secrets.")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not filepath:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "Address", "WIF"])
        writer.writerows(latest_secrets_rows)
    messagebox.showinfo("Exported", f"Secrets saved to:\n{filepath}\n\n⚠ Handle this file securely.")

def recover_wallet():
    # clear outputs
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

    # Validate mnemonic (checksum + words)
    try:
        Bip39MnemonicValidator(Bip39Languages.ENGLISH).Validate(seed_phrase)
    except Exception as e:
        wallet_output_box.insert(tk.END, f"Invalid BIP-39 mnemonic. {e}\n")
        wallet_output_box.config(state=tk.DISABLED)
        return

    try:
        passphrase = passphrase_var.get()
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate(passphrase)
        is_testnet = (network_var_wallet.get() == "Testnet")
        coin = Bip44Coins.BITCOIN_TESTNET if is_testnet else Bip44Coins.BITCOIN
        bip44_ctx = Bip44.FromSeed(seed_bytes, coin)

        # derive account/chain contexts
        acct = bip44_ctx.Purpose().Coin().Account(0)
        ext_chain = acct.Change(Bip44Changes.CHAIN_EXT)
        int_chain = acct.Change(Bip44Changes.CHAIN_INT)

        ext_n = max(0, int(num_addresses_var.get() or 0))
        chg_n = max(0, int(change_scan_var.get() or 0))

        wallet_output_box.insert(
            tk.END,
            f"Seed Valid. Network: {'Testnet' if is_testnet else 'Mainnet'}\n"
            f"Path base: m/44'/{1 if is_testnet else 0}'/0'\n"
            f"Passphrase: {'<set>' if passphrase else '<none>'}\n\n"
            f"Showing first {ext_n} external and {chg_n} change addresses (P2PKH):\n\n"
        )

        # external addresses
        for i in range(ext_n):
            addr_ctx = ext_chain.AddressIndex(i)
            addr = addr_ctx.PublicKey().ToAddress()
            path = f"m/44'/{1 if is_testnet else 0}'/0'/0/{i}"
            wallet_output_box.insert(tk.END, f"{path} → {addr}\n")

        # change addresses
        if chg_n:
            wallet_output_box.insert(tk.END, "\n")
        for i in range(chg_n):
            addr_ctx = int_chain.AddressIndex(i)
            addr = addr_ctx.PublicKey().ToAddress()
            path = f"m/44'/{1 if is_testnet else 0}'/0'/1/{i}"
            wallet_output_box.insert(tk.END, f"{path} → {addr}\n")

        # secrets (gated)
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

        # lock address box
        wallet_output_box.config(state=tk.DISABLED)

        # enable/disable secrets widgets according to gate
        state = tk.NORMAL if reveal_var.get() else tk.DISABLED
        xpub_entry.config(state=state)
        xprv_entry.config(state=state)
        wif_output_box.config(state=state)
        show_xprv_chk.config(state=state)
        export_secrets_btn.config(state=state)

    except Exception as e:
        wallet_output_box.insert(tk.END, f"Error: {str(e)}\n")
        wallet_output_box.config(state=tk.DISABLED)



# GUI setup
root = tk.Tk()
root.geometry('900x680')
root.title("Seed Phrase Validator & Recovery")
style = ttk.Style()
style.theme_use("winnative")
style.configure("TNotebook.Tab", width='70', anchor="center")
style.map("TNotebook.Tab",
          background=[("selected", "#21694f"),
                      ("!selected", "white")],
          foreground=[("selected", "white"),
                      ("!selected", "black")])

notebook = ttk.Notebook(root, style='TNotebook')
tab_wallet_recovery = ttk.Frame(notebook)
tab_seed_recovery = ttk.Frame(notebook)
notebook.add(tab_wallet_recovery, text='Wallet Recovery')
notebook.add(tab_seed_recovery, text='Seed Recovery')
notebook.pack(fill="both", expand=True)

# =========================
# wallet recovery tab
# =========================

tk.Label(tab_wallet_recovery, text="Wallet Recovery", font=("Arial", 20)).pack(pady=(10,5))

# Seed phrase input
tk.Label(tab_wallet_recovery, text="Enter your complete seed phrase (space-separated):").pack(pady=(0,5))
seed_entry = scrolledtext.ScrolledText(tab_wallet_recovery, wrap=tk.WORD, height=4, font=("Arial", 12))
seed_entry.pack(pady=10, padx=20, fill=tk.X)

# Optional passphrase (25th word)
pp_row = tk.Frame(tab_wallet_recovery)
pp_row.pack(padx=20, fill="x")
tk.Label(pp_row, text="BIP-39 passphrase (optional):").pack(side=tk.LEFT)
passphrase_var = tk.StringVar()
pp_entry = tk.Entry(pp_row, textvariable=passphrase_var, show="•", width=40)
pp_entry.pack(side=tk.LEFT, padx=(8,10))
pp_show_var = tk.BooleanVar(value=False)
def toggle_pp():
    pp_entry.config(show="" if pp_show_var.get() else "•")
tk.Checkbutton(pp_row, text="Show", variable=pp_show_var, command=toggle_pp).pack(side=tk.LEFT)

# Network + counts
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

rec_frame = tk.Frame(tab_wallet_recovery)
rec_frame.pack(pady=8)
btn_recover = tk.Button(rec_frame, text="Recover Wallet", command=recover_wallet)
btn_recover.pack(side=tk.LEFT, padx=10)

btn_export = tk.Button(rec_frame, text="Export Addresses (CSV)", command=export_wallet_addresses_csv)
btn_export.pack(side=tk.LEFT, padx=10)

export_secrets_btn = tk.Button(rec_frame, text="Export Secrets (CSV)", command=export_wallet_secrets_csv, state=tk.DISABLED)
export_secrets_btn.pack(side=tk.LEFT, padx=10)

# Output box (addresses)
addr_label = tk.Label(tab_wallet_recovery, text="Recovered wallet addresses:")
addr_label.pack(pady=(12, 0))
wallet_output_box = scrolledtext.ScrolledText(tab_wallet_recovery, wrap=tk.WORD, width=80, height=12, font=("Arial", 11))
wallet_output_box.pack(padx=10, pady=5, fill="both", expand=False)
wallet_output_box.config(state=tk.DISABLED)

# Secrets gate + panel
secrets_gate_row = tk.Frame(tab_wallet_recovery)
secrets_gate_row.pack(fill="x", padx=10, pady=(6, 0))
reveal_var = tk.BooleanVar(value=False)
def on_reveal_toggle():
    # enable/disable secrets widgets
    state = tk.NORMAL if reveal_var.get() else tk.DISABLED
    xpub_entry.config(state=state)
    xprv_entry.config(state=state)
    wif_output_box.config(state=state)
    show_xprv_chk.config(state=state)
    export_secrets_btn.config(state=state)

    # hide/show the address section to avoid duplication
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

tk.Checkbutton(secrets_gate_row,
               text="I understand the risks. Reveal secret keys (xprv / WIF).",
               variable=reveal_var, command=on_reveal_toggle).pack(anchor="w", padx=4)

secrets_frame = tk.LabelFrame(tab_wallet_recovery, text="Secrets (gated)")
secrets_frame.pack(fill="both", expand=True, padx=10, pady=(6, 10))

# xpub/xprv row
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
show_xprv_chk.grid(row=1, column=2, sticky="w", padx=(8,0))

keys_row.grid_columnconfigure(1, weight=1)

# WIF list
wif_frame = tk.Frame(secrets_frame)
wif_frame.pack(fill="both", expand=True, padx=6, pady=(0,6))
wif_output_box = scrolledtext.ScrolledText(wif_frame, wrap=tk.NONE, width=80, height=8, font=("Courier New", 10))
wif_output_box.pack(fill="both", expand=True)
wif_output_box.config(state=tk.DISABLED)

# Buttons
ctrl_frame = tk.Frame(tab_wallet_recovery)
ctrl_frame.pack(pady=10)


# Keep secrets widgets disabled initially
xpub_entry.config(state=tk.DISABLED)
xprv_entry.config(state=tk.DISABLED)
wif_output_box.config(state=tk.DISABLED)

# =========================
# seed recovery tab — ONLY seed input & output resize
# =========================

# Top title
tk.Label(tab_seed_recovery, text="Seed Recovery", font=("Arial", 20)).pack(pady=(10,5))

# ---------- RESIZABLE INPUT AREA ----------
input_area = tk.Frame(tab_seed_recovery)
input_area.pack(fill="both", expand=True, padx=10)          # <-- expands
tk.Label(
    input_area,
    text="Enter your seed phrase (space-separated). Use '*' for any word or 'prefix*' to expand by starting letters."
).pack()

text = scrolledtext.ScrolledText(input_area, wrap=tk.WORD, height=6, font=("Arial", 12))
text.pack(fill="both", expand=True, pady=(5, 0))            # <-- expands
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

text.bind("<KeyRelease>", on_key_release)
text.tag_configure("valid", foreground="darkgreen")
text.tag_configure("invalid", foreground="darkred")

word_count_label = tk.Label(tab_seed_recovery, text="Words: 0 | Valid: 0")
word_count_label.pack(padx=10, pady=(5, 0))

# Known address (fixed)
address_frame = tk.Frame(tab_seed_recovery)
address_frame.pack(pady=(10, 0), fill="x", padx=10)
tk.Label(address_frame, text="Enter your known wallet address (optional):").pack(side=tk.LEFT, padx=(0, 5))
known_address_entry = tk.Entry(address_frame, width=45)
known_address_entry.pack(side=tk.LEFT)

# BIP-39 passphrase (fixed)
pp_frame = tk.Frame(tab_seed_recovery)
pp_frame.pack(pady=(10, 0), fill="x", padx=10)
tk.Label(pp_frame, text="BIP-39 passphrase (optional):").pack(side=tk.LEFT, padx=(0, 5))
seed_pp_var = tk.StringVar()
seed_pp_entry = tk.Entry(pp_frame, textvariable=seed_pp_var, show="•")
seed_pp_entry.pack(side=tk.LEFT)
seed_pp_show_var = tk.BooleanVar(value=False)
def toggle_seed_pp():
    seed_pp_entry.config(show="" if seed_pp_show_var.get() else "•")
tk.Checkbutton(pp_frame, text="Show", variable=seed_pp_show_var, command=toggle_seed_pp).pack(side=tk.LEFT)

btn_frame = tk.Frame(tab_seed_recovery)
btn_frame.pack(pady=10)

tk.Label(btn_frame, text="Select Bitcoin Network:").grid(row=0, column=1)

network_var = tk.StringVar()
network_var.set("Mainnet")  # Default

network_menu = tk.OptionMenu(btn_frame, network_var, "Mainnet", "Testnet")
network_menu.grid(row=0, column=2, padx=(5, 10))

tk.Button(btn_frame, text="Recover Missing Word(s)", command=threaded_recover).grid(row=0, column=3, padx=10)
tk.Button(btn_frame, text="Export to File", command=lambda: export_seed_to_file()).grid(row=0, column=4, padx=10)


# ---------- RESIZABLE OUTPUT AREA ----------
output_area = tk.Frame(tab_seed_recovery)
output_area.pack(fill="both", expand=True, padx=10, pady=(5, 10))   # <-- expands
tk.Label(output_area, text="Recovered Seed Phrase Combinations:").pack(anchor="w")

seed_output_box = scrolledtext.ScrolledText(output_area, wrap=tk.WORD, width=68, height=10, font=("Arial", 11))
seed_output_box.pack(fill="both", expand=True, pady=(5, 0))         # <-- expands
seed_output_box.config(state=tk.DISABLED)

# keep a distinct export for seed tab
def export_seed_to_file():
    content = text.get("1.0", tk.END).strip()
    words = content.split()
    filename = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Seed Phrase")
    if filename:
        with open(filename, "w") as f:
            f.write(" ".join(words))
        messagebox.showinfo("Exported", f"Seed phrase saved to:\n{filename}")

# cache for secrets export
latest_secrets_rows = []

root.mainloop()
