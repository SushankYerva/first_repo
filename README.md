# 🪙 Wallet Recovery GUI (Tkinter)

A **Python-based Tkinter GUI** application designed for **seed phrase validation and wallet recovery**. It allows users to recover missing or partial wallet seed phrases by leveraging **BIP-39** and **BIP-44** standards. This application is specifically designed for cryptocurrency wallet recovery with support for **Mainnet** and **Testnet** addresses.

> **Legal & Ethical Use Only**: This tool should only be used for wallet recovery where you own the assets or have explicit permission to recover the wallet.

[![Build](https://github.com/SushankYerva/wallet_recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/SushankYerva/wallet_recovery/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-MIT-informational)

## Features

- **Seed Phrase Validation**: Checks the validity of seed phrases using **BIP-39**.
- **Wallet Recovery**: Recovers wallet addresses by generating candidate seed phrases.
- **Multi-address Support**: Supports both **P2PKH** and **Bech32** address types.
- **Progress Visualization**: Displays a progress bar with real-time updates while recovering wallet addresses.
- **Export Functionality**: Export recovered wallet addresses and secrets (e.g., **WIF**, **xpub**, **xprv**) as CSV files.

## Screenshots

![Wallet Recovery Screenshot](assets/screenshots/Wallet_recovery_tab.png)
_Example of the Wallet Recovery tab_

![Seed Recovery Screenshot](assets/screenshots/seed_recovery_tab.png)
_Example of the Seed Recovery tab_

## Quickstart

### Prerequisites

Make sure you have **Python 3.10+** installed. If not, install Python from [here](https://www.python.org/downloads/).

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/SushankYerva/wallet_recovery.git
   cd wallet-recovery-gui
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scriptsctivate
   # On macOS/Linux:
   source .venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the GUI:
   ```bash
   python -m src.gui
   ```

### Usage

1. **Seed Recovery**: Enter a partial or complete seed phrase and recover missing words.
2. **Wallet Recovery**: Enter the full seed phrase and recover wallet addresses.
3. **Exporting**: Export the recovered addresses and secrets into **CSV** files for secure storage.

## Testing

This project uses **pytest** for testing.

To run the tests:
```bash
pytest tests/
```

## CI Workflow

This project is integrated with **GitHub Actions** for continuous integration. The CI pipeline runs tests and ensures that the code is always in a working state. You can check the status of the build and tests directly in the [GitHub Actions tab](https://github.com/SushankYerva/wallet_recovery/actions).

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-name`).
6. Open a pull request.

## Acknowledgments

- **BIP-39** and **BIP-44** standards for wallet seed generation.
- **Tkinter** for the graphical user interface.
- **BipUtils** library for BIP-39/44 functionality.
- **Python Mnemonic** library for mnemonic phrase validation.
