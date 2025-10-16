import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import itertools

from bip39_recovery import (
    is_valid_mnemonic,
    WORDSET,
    MNEMONIC_OBJ
)
from key_derivation import mnemonic_to_seed, derive_bip44_address
from utils import normalize_mnemonic_input, words_to_phrase

# Default derivation paths for coins
DEFAULT_PATHS = {
    "bitcoin": "m/44'/0'/0'/0/0",
    "zcash":   "m/44'/133'/0'/0/0",
}

class RecoveryPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self._build_ui()

    def _build_ui(self):
        # Inputs: mnemonic and optional known address
        ttk.Label(self, text="Incomplete Mnemonic (use '_' for missing):").grid(row=0, column=0, sticky="w")
        self.txt_mnemonic = tk.Text(self, height=3, wrap="word")
        self.txt_mnemonic.grid(row=1, column=0, columnspan=3, sticky="ew")

        ttk.Label(self, text="Passphrase (optional):").grid(row=2, column=0, sticky="w", pady=(5,0))
        self.pass_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pass_var, width=30).grid(row=2, column=1, sticky="w", padx=5, pady=(5,0))

        ttk.Label(self, text="Known Address (optional):").grid(row=3, column=0, sticky="w")
        self.known_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.known_var, width=40).grid(row=3, column=1, columnspan=2, sticky="ew")

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(btn_frame, text="Recover Keys", command=self._on_recover_keys).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Recover Missing", command=self._on_recover_missing).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="← Back", command=lambda: self.controller.show_frame("HomePage")).pack(side="left", padx=5)

        # Output area
        self.txt_output = ScrolledText(self, height=12, wrap="word", state="disabled")
        self.txt_output.grid(row=5, column=0, columnspan=3, sticky="nsew")

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def _clear_output(self):
        self.txt_output.configure(state="normal")
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.configure(state="disabled")

    def _append_output(self, text: str):
        self.txt_output.configure(state="normal")
        self.txt_output.insert(tk.END, text + "\n")
        self.txt_output.see(tk.END)
        self.txt_output.configure(state="disabled")

    def _derive_first(self, phrase: str) -> str:
        seed = mnemonic_to_seed(phrase, self.pass_var.get().strip())
        return derive_bip44_address(seed, coin="bitcoin", account=0, change=0, address_index=0)["address"]

    def _on_recover_keys(self):
        self._clear_output()
        raw = self.txt_mnemonic.get("1.0", tk.END)
        words = normalize_mnemonic_input(raw)
        phrase = words_to_phrase(words)
        if not is_valid_mnemonic(phrase):
            self._append_output("❌ Invalid mnemonic or checksum mismatch.")
            return
        addr_known = self.known_var.get().strip()
        addr = self._derive_first(phrase)
        if addr_known and addr != addr_known:
            self._append_output(f"❌ First address {addr} does not match known {addr_known}")
            return
        self._append_output("✅ Full mnemonic validated:")
        self._append_output(phrase)
        self._append_output(f"→ First address: {addr}")

    def _on_recover_missing(self):
        self._clear_output()
        raw = self.txt_mnemonic.get("1.0", tk.END)
        parts = normalize_mnemonic_input(raw)
        missing_idxs = [i for i,w in enumerate(parts) if w == "_"]
        if not missing_idxs:
            self._append_output("❌ No '_' placeholders found.")
            return
        # Run brute-force in background
        def worker():
            found = []
            for combo in itertools.product(WORDSET, repeat=len(missing_idxs)):
                trial = parts.copy()
                for idx, w in zip(missing_idxs, combo):
                    trial[idx] = w
                phrase = words_to_phrase(trial)
                if MNEMONIC_OBJ.check(phrase):
                    found.append(phrase)
            if not found:
                self._append_output("❌ No valid mnemonic found.")
                return
            addr_known = self.known_var.get().strip()
            if addr_known:
                found = [p for p in found if self._derive_first(p) == addr_known]
            self._append_output(f"✅ Found {len(found)} candidate(s):")
            for p in found:
                self._append_output(f" - {p}\n   → {self._derive_first(p)}")

        threading.Thread(target=worker, daemon=True).start()