"""
Tests for src/crypto_db.py – Phase 1.

Covers:
  * Key derivation determinism and uniqueness
  * Field encryption / decryption round-trip
  * Vault initialisation & unlock (correct and wrong passwords)
  * Full CRUD operations on entries
  * Change master password
  * Lock / unlock lifecycle
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.crypto_db import (
    DatabaseManager,
    derive_key,
    encrypt_field,
    decrypt_field,
)
from cryptography.fernet import Fernet


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_vault.db"


@pytest.fixture()
def unlocked_db(tmp_db_path: Path) -> DatabaseManager:
    """Return an open, initialised and unlocked DatabaseManager."""
    db = DatabaseManager()
    db.open(tmp_db_path)
    db.initialize_vault("CorrectHorseBatteryStaple!")
    return db


# ──────────────────────────────────────────────────────────────────────────────
# Key derivation
# ──────────────────────────────────────────────────────────────────────────────

class TestKeyDerivation:
    def test_same_inputs_produce_same_key(self) -> None:
        salt = os.urandom(32)
        k1 = derive_key("password", salt)
        k2 = derive_key("password", salt)
        assert k1 == k2

    def test_different_salts_produce_different_keys(self) -> None:
        k1 = derive_key("password", os.urandom(32))
        k2 = derive_key("password", os.urandom(32))
        assert k1 != k2

    def test_different_passwords_produce_different_keys(self) -> None:
        salt = os.urandom(32)
        k1 = derive_key("pass1", salt)
        k2 = derive_key("pass2", salt)
        assert k1 != k2

    def test_derived_key_is_valid_fernet_key(self) -> None:
        key = derive_key("test", os.urandom(32))
        # Should not raise
        Fernet(key)


# ──────────────────────────────────────────────────────────────────────────────
# Field encryption helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryptField:
    def _fernet(self) -> Fernet:
        return Fernet(derive_key("pw", os.urandom(32)))

    def test_round_trip(self) -> None:
        f = self._fernet()
        original = "super secret value"
        assert decrypt_field(f, encrypt_field(f, original)) == original

    def test_empty_string_round_trip(self) -> None:
        f = self._fernet()
        assert decrypt_field(f, encrypt_field(f, "")) == ""

    def test_unicode_round_trip(self) -> None:
        f = self._fernet()
        text = "🔐 Pässwörð ñoñ-ASCII"
        assert decrypt_field(f, encrypt_field(f, text)) == text

    def test_ciphertext_differs_from_plaintext(self) -> None:
        f = self._fernet()
        plaintext = "plaintext"
        ciphertext = encrypt_field(f, plaintext)
        assert plaintext.encode() not in ciphertext


# ──────────────────────────────────────────────────────────────────────────────
# DatabaseManager – vault lifecycle
# ──────────────────────────────────────────────────────────────────────────────

class TestVaultLifecycle:
    def test_new_vault_is_not_initialised(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        assert not db.is_initialized()
        db.close()

    def test_initialize_vault_marks_as_initialised(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        assert db.is_initialized()
        db.close()

    def test_initialize_vault_twice_raises(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        with pytest.raises(ValueError):
            db.initialize_vault("masterpass")
        db.close()

    def test_unlock_correct_password(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        db.lock()
        assert not db.is_unlocked
        assert db.unlock("masterpass")
        assert db.is_unlocked
        db.close()

    def test_unlock_wrong_password_returns_false(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        db.lock()
        assert not db.unlock("wrongpassword")
        db.close()

    def test_unlock_uninitialised_vault_raises(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        with pytest.raises(RuntimeError):
            db.unlock("anything")
        db.close()

    def test_lock_clears_fernet(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        assert db.is_unlocked
        db.lock()
        assert not db.is_unlocked
        db.close()

    def test_operations_fail_when_locked(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        db.lock()
        with pytest.raises(RuntimeError):
            db.get_all_entries()
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# DatabaseManager – CRUD
# ──────────────────────────────────────────────────────────────────────────────

class TestCRUD:
    def test_add_and_retrieve_entry(self, unlocked_db: DatabaseManager) -> None:
        entry_id = unlocked_db.add_entry(
            "GitHub", "alice@example.com", "hunter2", "https://github.com", "dev"
        )
        assert isinstance(entry_id, int)
        entry = unlocked_db.get_entry(entry_id)
        assert entry is not None
        assert entry["title"] == "GitHub"
        assert entry["username"] == "alice@example.com"
        assert entry["password"] == "hunter2"
        assert entry["url"] == "https://github.com"
        assert entry["notes"] == "dev"

    def test_get_all_entries(self, unlocked_db: DatabaseManager) -> None:
        unlocked_db.add_entry("Site A", "user1", "pass1", "http://a.com", "")
        unlocked_db.add_entry("Site B", "user2", "pass2", "http://b.com", "note")
        entries = unlocked_db.get_all_entries()
        assert len(entries) == 2
        titles = {e["title"] for e in entries}
        assert titles == {"Site A", "Site B"}

    def test_get_nonexistent_entry_returns_none(self, unlocked_db: DatabaseManager) -> None:
        assert unlocked_db.get_entry(9999) is None

    def test_update_entry(self, unlocked_db: DatabaseManager) -> None:
        entry_id = unlocked_db.add_entry("Old Title", "user", "pass", "", "")
        updated = unlocked_db.update_entry(
            entry_id, "New Title", "newuser", "newpass", "http://new.com", "updated"
        )
        assert updated
        entry = unlocked_db.get_entry(entry_id)
        assert entry["title"] == "New Title"
        assert entry["password"] == "newpass"

    def test_update_nonexistent_entry_returns_false(
        self, unlocked_db: DatabaseManager
    ) -> None:
        assert not unlocked_db.update_entry(9999, "t", "u", "p", "", "")

    def test_delete_entry(self, unlocked_db: DatabaseManager) -> None:
        entry_id = unlocked_db.add_entry("ToDelete", "u", "p", "", "")
        assert unlocked_db.delete_entry(entry_id)
        assert unlocked_db.get_entry(entry_id) is None

    def test_delete_nonexistent_entry_returns_false(
        self, unlocked_db: DatabaseManager
    ) -> None:
        assert not unlocked_db.delete_entry(9999)

    def test_encrypted_data_not_plaintext_in_db_file(
        self, tmp_db_path: Path
    ) -> None:
        """Verify raw file bytes do not contain the stored password."""
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("masterpass")
        db.add_entry("Test", "testuser", "supersecretpassword", "http://x.com", "")
        db.close()

        raw = tmp_db_path.read_bytes()
        assert b"supersecretpassword" not in raw


# ──────────────────────────────────────────────────────────────────────────────
# Change master password
# ──────────────────────────────────────────────────────────────────────────────

class TestChangeMasterPassword:
    def test_change_password_success(self, tmp_db_path: Path) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("oldpass")
        db.add_entry("entry", "user", "pw", "", "")

        assert db.change_master_password("oldpass", "newpass")
        db.lock()
        assert not db.unlock("oldpass")
        assert db.unlock("newpass")
        db.close()

    def test_change_password_wrong_current_returns_false(
        self, tmp_db_path: Path
    ) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("correctpass")
        assert not db.change_master_password("wrongpass", "newpass")
        db.close()

    def test_entries_preserved_after_password_change(
        self, tmp_db_path: Path
    ) -> None:
        db = DatabaseManager()
        db.open(tmp_db_path)
        db.initialize_vault("oldpass")
        db.add_entry("MyBank", "alice", "s3cr3t", "https://bank.com", "VIP")
        db.change_master_password("oldpass", "newpass")
        db.lock()
        db.unlock("newpass")

        entries = db.get_all_entries()
        assert len(entries) == 1
        assert entries[0]["title"] == "MyBank"
        assert entries[0]["password"] == "s3cr3t"
        db.close()
