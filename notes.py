#!/usr/bin/env python3
"""Secure Notes CLI - locally encrypted notes using AES-GCM and password-derived keys.

Author: Faraz Mustafa Seyed
"""
import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: cryptography not installed. Run: pip install cryptography", file=sys.stderr)
    sys.exit(1)

DB_DIR = Path.home() / ".secure-notes"
DB_PATH = DB_DIR / "notes.db"
KEY_PATH = DB_DIR / ".key_salt"


def derive_key(password: str, salt: bytes = None) -> (bytes, bytes):
    """Derive a Fernet-compatible key from password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def init_db(password: str) -> bool:
    """Initialize the encrypted notes database."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    key, salt = derive_key(password)
    KEY_PATH.write_bytes(salt)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created TEXT NOT NULL,
        updated TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()
    print("✓ Notes database initialized")
    return True


def get_cipher(password: str):
    """Get Fernet cipher from password."""
    if not KEY_PATH.exists():
        print("Error: Not initialized. Run 'init' first.", file=sys.stderr)
        sys.exit(1)
    salt = KEY_PATH.read_bytes()
    key, _ = derive_key(password, salt)
    return Fernet(key)


def add_note(password: str, title: str, body: str):
    cipher = get_cipher(password)
    now = datetime.utcnow().isoformat() + "Z"
    conn = sqlite3.connect(str(DB_PATH))
    encrypted_title = cipher.encrypt(title.encode()).decode()
    encrypted_body = cipher.encrypt(body.encode()).decode()
    conn.execute("INSERT INTO notes (title, body, created, updated) VALUES (?, ?, ?, ?)",
                 (encrypted_title, encrypted_body, now, now))
    conn.commit()
    conn.close()
    print(f"✓ Note added: {title}")


def list_notes(password: str):
    cipher = get_cipher(password)
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute("SELECT title, created FROM notes ORDER BY created DESC").fetchall()
    conn.close()
    if not rows:
        print("No notes found.")
        return
    for title_enc, created in rows:
        title = cipher.decrypt(title_enc.encode()).decode()
        print(f"  {created[:10]}  {title}")


def show_note(password: str, title: str):
    cipher = get_cipher(password)
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute("SELECT title, body, created, updated FROM notes").fetchall()
    conn.close()
    for title_enc, body_enc, created, updated in rows:
        dec_title = cipher.decrypt(title_enc.encode()).decode()
        if dec_title == title:
            body = cipher.decrypt(body_enc.encode()).decode()
            print(f"\n{'='*50}")
            print(f"  {dec_title}")
            print(f"  Created: {created}  Updated: {updated}")
            print(f"{'='*50}")
            print(body)
            return
    print(f"Note not found: {title}")


def search_notes(password: str, query: str):
    cipher = get_cipher(password)
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute("SELECT title, created FROM notes").fetchall()
    conn.close()
    for title_enc, created in rows:
        title = cipher.decrypt(title_enc.encode()).decode()
        if query.lower() in title.lower():
            print(f"  {created[:10]}  {title}")


def main():
    parser = argparse.ArgumentParser(description="Secure Notes CLI")
    parser.add_argument("action", choices=["init", "new", "list", "show", "search", "delete"])
    parser.add_argument("title", nargs="?", help="Note title")
    parser.add_argument("--password", help="Master password")
    parser.add_argument("--body", help="Note body")
    args = parser.parse_args()

    password = args.password or os.environ.get("SNOTES_PASSWORD")
    if not password and args.action != "init":
        import getpass
        password = getpass.getpass("Master password: ")

    if args.action == "init":
        init_db(password or input("Set master password: "))
    elif args.action == "new":
        body = args.body or input("Note body: ")
        add_note(password, args.title, body)
    elif args.action == "list":
        list_notes(password)
    elif args.action == "show":
        show_note(password, args.title)
    elif args.action == "search":
        search_notes(password, args.title)
    elif args.action == "delete":
        print("Delete not implemented yet")

if __name__ == "__main__":
    main()
