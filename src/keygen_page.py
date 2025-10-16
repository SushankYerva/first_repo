import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from mnemonic import Mnemonic
from key_derivation import derive_bip44_address, mnemonic_to_seed

# Allowed BIP-39 lengths
VALID_COUNTS = {12, 15, 18, 21, 24}

class KeyGenPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self._build_ui()

    def _build_ui(self):
        # Title
        ttk.Label(self, text="Key Generation", font=(None, 16)).grid(row=0, column=0, columnspan=2, pady=(0,10))

        # Passphrase input
        ttk.Label(self, text="Passphrase (optional):").grid(row=1, column=0, sticky="w")
        self.pass_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pass_var, width=30).grid(row=1, column=1, sticky="ew")

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Generate", command=self._on_generate).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="← Back", command=lambda: self.controller.show_frame("HomePage")).pack(side="left")

        # Output area
        self.txt_output = ScrolledText(self, height=10, wrap="word", state="disabled")
        self.txt_output.grid(row=3, column=0, columnspan=2, sticky="nsew")

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

    def _on_generate(self):
        self._clear_output()
        # Generate a 12-word mnemonic
        mnemo = Mnemonic("english")
        phrase = mnemo.generate(strength=128)
        passphrase = self.pass_var.get().strip()
        # Derive seed
        seed = mnemonic_to_seed(phrase, passphrase)
        # Derive first BIP-44 address
        info = derive_bip44_address(seed, coin="bitcoin", account=0, change=0, address_index=0)

        self._append_output("✅ Mnemonic (12 words):")
        self._append_output(phrase)
        self._append_output(f"\nSeed (hex): {seed.hex()}")
        self._append_output(f"First BTC Address: {info['address']}")