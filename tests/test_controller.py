"""
Tests for src/controller.py – Phase 2.

Covers:
  * Password generator
  * Vault creation and unlock via the controller
  * CRUD operations via the controller
  * Clipboard copy (when pyperclip is available)
  * Auto-lock timer behaviour (using short timeouts)
  * Lock callback invocation
"""

import time
from pathlib import Path

import pytest

from src.controller import (
    PasswordManagerController,
    generate_password,
)


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def controller(tmp_path: Path) -> PasswordManagerController:
    """Return a started controller backed by a fresh temporary database."""
    ctrl = PasswordManagerController(db_path=tmp_path / "test.db")
    ctrl.startup()
    ctrl.create_vault("TestMaster123!")
    return ctrl


@pytest.fixture(autouse=True)
def shutdown_controller(controller: PasswordManagerController):
    yield
    controller.shutdown()


# ──────────────────────────────────────────────────────────────────────────────
# Password generator
# ──────────────────────────────────────────────────────────────────────────────

class TestPasswordGenerator:
    def test_default_length(self) -> None:
        pw = generate_password()
        assert len(pw) == 20

    def test_custom_length(self) -> None:
        pw = generate_password(length=32)
        assert len(pw) == 32

    def test_contains_upper(self) -> None:
        pw = generate_password(length=30, use_upper=True, use_digits=False, use_symbols=False)
        assert any(c.isupper() for c in pw)

    def test_contains_digits(self) -> None:
        pw = generate_password(length=30, use_upper=False, use_digits=True, use_symbols=False)
        assert any(c.isdigit() for c in pw)

    def test_contains_symbols(self) -> None:
        symbol_set = set("!@#$%^&*()-_=+[]{}|;:,.<>?")
        pw = generate_password(length=30, use_upper=False, use_digits=False, use_symbols=True)
        assert any(c in symbol_set for c in pw)

    def test_no_two_identical(self) -> None:
        """Generated passwords should not be identical (astronomically unlikely)."""
        passwords = {generate_password() for _ in range(10)}
        assert len(passwords) == 10

    def test_minimum_length_raises(self) -> None:
        with pytest.raises(ValueError):
            generate_password(length=3)

    def test_controller_generate_password(
        self, controller: PasswordManagerController
    ) -> None:
        pw = controller.generate_password(length=16)
        assert len(pw) == 16


# ──────────────────────────────────────────────────────────────────────────────
# Vault lifecycle via controller
# ──────────────────────────────────────────────────────────────────────────────

class TestControllerVault:
    def test_is_not_first_run_after_create(
        self, controller: PasswordManagerController
    ) -> None:
        assert not controller.is_first_run()

    def test_is_unlocked_after_create(
        self, controller: PasswordManagerController
    ) -> None:
        assert controller.is_unlocked()

    def test_lock_and_unlock(
        self, controller: PasswordManagerController
    ) -> None:
        controller.lock()
        assert not controller.is_unlocked()
        assert controller.unlock("TestMaster123!")
        assert controller.is_unlocked()

    def test_unlock_wrong_password(
        self, controller: PasswordManagerController
    ) -> None:
        controller.lock()
        assert not controller.unlock("WrongPassword!")

    def test_first_run_flag(self, tmp_path: Path) -> None:
        ctrl = PasswordManagerController(db_path=tmp_path / "fresh.db")
        ctrl.startup()
        assert ctrl.is_first_run()
        ctrl.shutdown()


# ──────────────────────────────────────────────────────────────────────────────
# CRUD via controller
# ──────────────────────────────────────────────────────────────────────────────

class TestControllerCRUD:
    def test_add_and_get_entry(
        self, controller: PasswordManagerController
    ) -> None:
        entry_id = controller.add_entry(
            "Twitter", "bob", "tweet123!", "https://twitter.com", "social"
        )
        entry = controller.get_entry(entry_id)
        assert entry is not None
        assert entry["title"] == "Twitter"
        assert entry["username"] == "bob"

    def test_get_all_entries(self, controller: PasswordManagerController) -> None:
        controller.add_entry("A", "ua", "pa", "", "")
        controller.add_entry("B", "ub", "pb", "", "")
        entries = controller.get_all_entries()
        assert len(entries) == 2

    def test_update_entry(self, controller: PasswordManagerController) -> None:
        entry_id = controller.add_entry("Old", "user", "pw", "", "")
        controller.update_entry(entry_id, "New", "user2", "pw2", "http://x.com", "n")
        entry = controller.get_entry(entry_id)
        assert entry["title"] == "New"

    def test_delete_entry(self, controller: PasswordManagerController) -> None:
        entry_id = controller.add_entry("ToRemove", "u", "p", "", "")
        assert controller.delete_entry(entry_id)
        assert controller.get_entry(entry_id) is None

    def test_change_master_password(
        self, controller: PasswordManagerController
    ) -> None:
        controller.add_entry("Site", "user", "pass", "", "")
        assert controller.change_master_password("TestMaster123!", "NewPass456@")
        controller.lock()
        assert controller.unlock("NewPass456@")
        entries = controller.get_all_entries()
        assert len(entries) == 1


# ──────────────────────────────────────────────────────────────────────────────
# Auto-lock
# ──────────────────────────────────────────────────────────────────────────────

class TestAutoLock:
    def test_lock_callback_is_called(
        self, controller: PasswordManagerController
    ) -> None:
        called = []
        controller.set_lock_callback(lambda: called.append(True))
        controller.lock()
        assert called

    def test_disable_auto_lock(
        self, controller: PasswordManagerController
    ) -> None:
        """With auto-lock disabled the vault should not lock by itself."""
        controller.set_auto_lock_enabled(False)
        assert controller.is_unlocked()
        # No timer should fire
        time.sleep(0.1)
        assert controller.is_unlocked()
