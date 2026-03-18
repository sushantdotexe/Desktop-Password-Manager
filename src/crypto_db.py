"""
Phase 1 – Cryptography & Database module.

Responsibilities:
  * Derive an AES/Fernet encryption key from the master password using
    PBKDF2HMAC (SHA-256, 600 000 iterations).
  * Verify the master password via a small encrypted "verification block"
    stored in the database.
  * Provide a thin SQLite abstraction that stores only encrypted blobs –
    no plaintext data is ever written to disk.

Database schema (single file, default: ~/.password_manager/vault.db):

    meta   – key-value store (salt, verification_block, version)
    entries – encrypted credential records

All entry fields (title, username, password, url, notes) are encrypted
individually before being stored so that even a column-level compromise
reveals nothing.
"""

import os
import sqlite3
import base64
import struct
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 600_000
_SALT_LENGTH = 32          # bytes
_VERIFICATION_PLAINTEXT = b"VAULT_OK"   # small sentinel value
_DB_VERSION = 1

DEFAULT_DB_PATH = Path.home() / ".password_manager" / "vault.db"


# ──────────────────────────────────────────────────────────────────────────────
# Key derivation
# ──────────────────────────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Return a 32-byte URL-safe base64-encoded Fernet key derived from
    *master_password* and *salt* using PBKDF2HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


# ──────────────────────────────────────────────────────────────────────────────
# Encryption / decryption helpers
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_field(fernet: Fernet, plaintext: str) -> bytes:
    """Encrypt a plaintext string and return the ciphertext bytes."""
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt_field(fernet: Fernet, ciphertext: bytes) -> str:
    """Decrypt ciphertext bytes and return the original plaintext string."""
    return fernet.decrypt(ciphertext).decode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# DatabaseManager
# ──────────────────────────────────────────────────────────────────────────────

class DatabaseManager:
    """Manages the encrypted SQLite vault.

    Lifecycle
    ---------
    1. Call ``open(db_path)`` to connect.
    2. Call ``initialize_vault(master_password)`` the first time (creates tables,
       stores salt + verification block).
    3. On subsequent runs call ``unlock(master_password)`` which verifies the
       password and sets the active Fernet instance.
    4. Use the CRUD methods to read/write entries.
    5. Call ``lock()`` to discard the in-memory key.
    6. Call ``close()`` to close the database connection.
    """

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self._fernet: Fernet | None = None

    # ── connection ────────────────────────────────────────────────────────────

    def open(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        """Open (or create) the SQLite database at *db_path*."""
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def close(self) -> None:
        """Lock and close the database connection."""
        self.lock()
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── schema ────────────────────────────────────────────────────────────────

    def _create_schema(self) -> None:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                title      BLOB NOT NULL,
                username   BLOB NOT NULL,
                password   BLOB NOT NULL,
                url        BLOB NOT NULL,
                notes      BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        self._conn.commit()

    # ── vault initialisation / unlocking ─────────────────────────────────────

    def is_initialized(self) -> bool:
        """Return *True* if the vault already has a salt (i.e. has been set up)."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'salt'"
        ).fetchone()
        return row is not None

    def initialize_vault(self, master_password: str) -> None:
        """Create a new vault secured by *master_password*.

        Raises ``ValueError`` if the vault is already initialised.
        """
        if self.is_initialized():
            raise ValueError("Vault is already initialised.")
        salt = secrets.token_bytes(_SALT_LENGTH)
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        verification_block = fernet.encrypt(_VERIFICATION_PLAINTEXT)

        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO meta (key, value) VALUES ('salt', ?)", (salt,)
        )
        cur.execute(
            "INSERT INTO meta (key, value) VALUES ('verification_block', ?)",
            (verification_block,),
        )
        cur.execute(
            "INSERT INTO meta (key, value) VALUES ('version', ?)",
            (struct.pack(">I", _DB_VERSION),),
        )
        self._conn.commit()

        # Activate Fernet for immediate use
        self._fernet = fernet

        # Clear key material from local variables
        del key, master_password

    def unlock(self, master_password: str) -> bool:
        """Attempt to unlock the vault with *master_password*.

        Returns ``True`` on success, ``False`` if the password is wrong.
        Raises ``RuntimeError`` if the vault has not been initialised.
        """
        if not self.is_initialized():
            raise RuntimeError("Vault has not been initialised yet.")

        salt_row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'salt'"
        ).fetchone()
        vb_row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'verification_block'"
        ).fetchone()

        salt = bytes(salt_row["value"])
        verification_block = bytes(vb_row["value"])

        key = derive_key(master_password, salt)
        fernet = Fernet(key)

        try:
            plaintext = fernet.decrypt(verification_block)
        except InvalidToken:
            del key, master_password
            return False

        if plaintext != _VERIFICATION_PLAINTEXT:
            del key, master_password
            return False

        self._fernet = fernet
        del key, master_password
        return True

    def lock(self) -> None:
        """Discard the in-memory Fernet key (locks the vault)."""
        self._fernet = None

    @property
    def is_unlocked(self) -> bool:
        return self._fernet is not None

    # ── CRUD helpers ──────────────────────────────────────────────────────────

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        return self._fernet

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
    ) -> int:
        """Encrypt all fields and insert a new entry.  Returns the new row id."""
        f = self._require_unlocked()
        cur = self._conn.cursor()
        cur.execute(
            """INSERT INTO entries (title, username, password, url, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (
                encrypt_field(f, title),
                encrypt_field(f, username),
                encrypt_field(f, password),
                encrypt_field(f, url),
                encrypt_field(f, notes),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_all_entries(self) -> list[dict]:
        """Return all entries as a list of plain-text dicts."""
        f = self._require_unlocked()
        rows = self._conn.execute(
            "SELECT id, title, username, password, url, notes, created_at, updated_at "
            "FROM entries ORDER BY id"
        ).fetchall()
        result = []
        for row in rows:
            result.append(
                {
                    "id": row["id"],
                    "title": decrypt_field(f, bytes(row["title"])),
                    "username": decrypt_field(f, bytes(row["username"])),
                    "password": decrypt_field(f, bytes(row["password"])),
                    "url": decrypt_field(f, bytes(row["url"])),
                    "notes": decrypt_field(f, bytes(row["notes"])),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        return result

    def get_entry(self, entry_id: int) -> dict | None:
        """Return a single entry by *entry_id*, or *None* if not found."""
        f = self._require_unlocked()
        row = self._conn.execute(
            "SELECT id, title, username, password, url, notes, created_at, updated_at "
            "FROM entries WHERE id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "title": decrypt_field(f, bytes(row["title"])),
            "username": decrypt_field(f, bytes(row["username"])),
            "password": decrypt_field(f, bytes(row["password"])),
            "url": decrypt_field(f, bytes(row["url"])),
            "notes": decrypt_field(f, bytes(row["notes"])),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_entry(
        self,
        entry_id: int,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
    ) -> bool:
        """Update an existing entry.  Returns *True* if a row was modified."""
        f = self._require_unlocked()
        cur = self._conn.cursor()
        cur.execute(
            """UPDATE entries
               SET title    = ?,
                   username = ?,
                   password = ?,
                   url      = ?,
                   notes    = ?,
                   updated_at = datetime('now')
               WHERE id = ?""",
            (
                encrypt_field(f, title),
                encrypt_field(f, username),
                encrypt_field(f, password),
                encrypt_field(f, url),
                encrypt_field(f, notes),
                entry_id,
            ),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def delete_entry(self, entry_id: int) -> bool:
        """Delete an entry by *entry_id*.  Returns *True* if a row was deleted."""
        self._require_unlocked()
        cur = self._conn.cursor()
        cur.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def change_master_password(
        self, current_password: str, new_password: str
    ) -> bool:
        """Re-encrypt the entire vault with *new_password*.

        Returns *True* on success, *False* if *current_password* is wrong.
        """
        if not self.unlock(current_password):
            return False

        # Re-encrypt all entries with a brand-new salt + key
        all_entries = self.get_all_entries()

        new_salt = secrets.token_bytes(_SALT_LENGTH)
        new_key = derive_key(new_password, new_salt)
        new_fernet = Fernet(new_key)
        new_verification_block = new_fernet.encrypt(_VERIFICATION_PLAINTEXT)

        cur = self._conn.cursor()
        # Update meta
        cur.execute(
            "UPDATE meta SET value = ? WHERE key = 'salt'", (new_salt,)
        )
        cur.execute(
            "UPDATE meta SET value = ? WHERE key = 'verification_block'",
            (new_verification_block,),
        )

        # Re-encrypt every entry
        for entry in all_entries:
            cur.execute(
                """UPDATE entries
                   SET title    = ?,
                       username = ?,
                       password = ?,
                       url      = ?,
                       notes    = ?
                   WHERE id = ?""",
                (
                    encrypt_field(new_fernet, entry["title"]),
                    encrypt_field(new_fernet, entry["username"]),
                    encrypt_field(new_fernet, entry["password"]),
                    encrypt_field(new_fernet, entry["url"]),
                    encrypt_field(new_fernet, entry["notes"]),
                    entry["id"],
                ),
            )

        self._conn.commit()
        self._fernet = new_fernet
        del new_key, current_password, new_password
        return True
