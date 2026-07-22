# Secure Notes CLI

> Local encrypted notes CLI using AES-GCM with password-derived keys.

## Features

- 🔐 AES-256-GCM encryption
- 🔑 Password-derived key (Argon2id / PBKDF2)
- 📝 Create, read, list, delete notes
- 🔍 Search notes by title
- 💾 SQLite-backed storage

## Usage

```bash
pip install cryptography
python3 notes.py init
python3 notes.py new "My Note" --body "Secret content"
python3 notes.py list
python3 notes.py show "My Note"
python3 notes.py search "secret"
```

## Why I built this

I wanted a lightweight, local-only encrypted notes app for storing credentials and sensitive info. AES-256-GCM with a password-derived key means the data is useless without the passphrase.

— Faraz

## License
MIT — © 2026 Faraz Mustafa Seyed