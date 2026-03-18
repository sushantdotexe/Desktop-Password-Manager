# Desktop Password Manager

A secure, cross-platform desktop password manager built with Python, inspired by KeePass.

## Features

- 🔐 **Master password protection** — vault stays fully encrypted at rest; master password is never stored
- 🔑 **Strong encryption** — PBKDF2HMAC-SHA256 (600,000 iterations) key derivation + AES-128 via Fernet
- 🗄️ **Encrypted SQLite storage** — every field (title, username, password, URL, notes) is individually encrypted before being written to disk
- ➕ **Full CRUD** — add, edit, delete, and search credential entries
- 🔒 **Auto-lock** — vault locks automatically after 5 minutes of idle time; manual Lock button always available
- 📋 **Clipboard management** — copy password to clipboard with automatic clear after 10 seconds
- ⚙️ **Password generator** — cryptographically secure random passwords (configurable length, uppercase, digits, symbols)
- 🚀 **Launch & Auto-Type** — opens the stored URL in the default browser, then automatically types username, TAB, password, ENTER
- 🔄 **Change master password** — re-encrypts the entire vault with the new key

## Project Structure

```
Desktop-Password-Manager/
├── main.py              # CLI entry point
├── requirements.txt     # Python dependencies
├── src/
│   ├── __init__.py
│   ├── crypto_db.py     # Phase 1: Cryptography + SQLite database layer
│   ├── controller.py    # Phase 2: Business logic, password gen, clipboard, auto-type
│   └── gui.py           # Phase 3: customtkinter GUI
└── tests/
    ├── __init__.py
    ├── test_crypto_db.py
    └── test_controller.py
```

## Requirements

- Python 3.12+
- See `requirements.txt` for Python package dependencies

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Launch the application (vault stored at ~/.password_manager/vault.db)
python main.py

# Use a custom database path
python main.py --db /path/to/my/vault.db
```

On first launch you will be prompted to create a master password. On subsequent launches you unlock the vault with that password.

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Security Notes

- The master password is **never stored** anywhere — only a short encrypted verification block is kept so the app can detect an incorrect password
- All database fields are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before being written to SQLite
- The encryption key is derived from the master password using PBKDF2HMAC-SHA256 with a random 32-byte salt and 600,000 iterations
- The key is held only in memory and discarded when the vault is locked
- Clipboard is automatically cleared 10 seconds after copying a password

## Tech Stack

| Layer | Technology |
|---|---|
| GUI | [customtkinter](https://github.com/TomSchimansky/CustomTkinter) |
| Cryptography | [cryptography](https://cryptography.io) — Fernet + PBKDF2HMAC |
| Storage | SQLite 3 (stdlib) |
| Auto-Type | [pyautogui](https://pyautogui.readthedocs.io) |
| Clipboard | [pyperclip](https://pypi.org/project/pyperclip/) |
