"""
Phase 2 – Controller / Business Logic module.

Responsibilities:
  * Wrap ``DatabaseManager`` and expose a high-level API for the GUI.
  * Implement a secure password generator.
  * Manage clipboard operations with an auto-clear timer.
  * Implement the "Launch & Auto-Type" feature.
  * Handle idle-detection and auto-lock.
"""

import secrets
import string
import threading
import time
import webbrowser
from collections.abc import Callable
from pathlib import Path

try:
    import pyautogui
    _PYAUTOGUI_AVAILABLE = True
except Exception:
    _PYAUTOGUI_AVAILABLE = False

try:
    import pyperclip
    _PYPERCLIP_AVAILABLE = True
except ImportError:
    _PYPERCLIP_AVAILABLE = False

from src.crypto_db import DatabaseManager, DEFAULT_DB_PATH

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

CLIPBOARD_CLEAR_DELAY = 10   # seconds
AUTO_LOCK_DELAY = 300        # seconds (5 minutes)
AUTO_TYPE_WAIT = 4           # seconds to wait for page to load

_PASSWORD_LOWER = string.ascii_lowercase
_PASSWORD_UPPER = string.ascii_uppercase
_PASSWORD_DIGITS = string.digits
_PASSWORD_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


# ──────────────────────────────────────────────────────────────────────────────
# Password Generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Return a cryptographically secure random password.

    Guarantees at least one character from each requested category so that
    common complexity policies are satisfied.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    alphabet = _PASSWORD_LOWER
    required: list[str] = [secrets.choice(_PASSWORD_LOWER)]

    if use_upper:
        alphabet += _PASSWORD_UPPER
        required.append(secrets.choice(_PASSWORD_UPPER))
    if use_digits:
        alphabet += _PASSWORD_DIGITS
        required.append(secrets.choice(_PASSWORD_DIGITS))
    if use_symbols:
        alphabet += _PASSWORD_SYMBOLS
        required.append(secrets.choice(_PASSWORD_SYMBOLS))

    remaining_length = length - len(required)
    if remaining_length < 0:
        remaining_length = 0

    random_chars = [secrets.choice(alphabet) for _ in range(remaining_length)]
    password_chars = required + random_chars

    # Fisher-Yates shuffle using secrets for uniform distribution
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


# ──────────────────────────────────────────────────────────────────────────────
# PasswordManagerController
# ──────────────────────────────────────────────────────────────────────────────

class PasswordManagerController:
    """High-level controller used by the GUI layer.

    The GUI should only interact with this class, never with
    ``DatabaseManager`` directly.
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self._db = DatabaseManager()
        self._db_path = Path(db_path)
        self._lock_callback: Callable[[], None] | None = None

        # Auto-lock timer
        self._last_activity = time.monotonic()
        self._auto_lock_timer: threading.Timer | None = None
        self._auto_lock_enabled = True

        # Clipboard clear timer
        self._clipboard_timer: threading.Timer | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def startup(self) -> None:
        """Open the database.  Must be called before any other method."""
        self._db.open(self._db_path)

    def shutdown(self) -> None:
        """Lock and close the database."""
        self._cancel_auto_lock()
        self._cancel_clipboard_timer()
        self._db.close()

    # ── vault setup / authentication ──────────────────────────────────────────

    def is_first_run(self) -> bool:
        """Return *True* when no vault exists yet."""
        return not self._db.is_initialized()

    def create_vault(self, master_password: str) -> None:
        """Initialise a brand-new vault with *master_password*."""
        self._db.initialize_vault(master_password)
        self._start_auto_lock_timer()

    def unlock(self, master_password: str) -> bool:
        """Unlock the vault.  Returns *True* on success."""
        result = self._db.unlock(master_password)
        if result:
            self._reset_activity()
            self._start_auto_lock_timer()
        return result

    def lock(self) -> None:
        """Lock the vault and cancel background timers."""
        self._cancel_auto_lock()
        self._cancel_clipboard_timer()
        self._db.lock()
        if self._lock_callback:
            self._lock_callback()

    def is_unlocked(self) -> bool:
        return self._db.is_unlocked

    def set_lock_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback that is invoked when the vault is locked."""
        self._lock_callback = callback

    def change_master_password(
        self, current_password: str, new_password: str
    ) -> bool:
        """Return *True* if the master password was changed successfully."""
        result = self._db.change_master_password(current_password, new_password)
        if result:
            self._reset_activity()
        return result

    # ── activity / auto-lock ──────────────────────────────────────────────────

    def _reset_activity(self) -> None:
        self._last_activity = time.monotonic()

    def record_activity(self) -> None:
        """Call this from the GUI on any user interaction to reset the idle timer."""
        self._reset_activity()
        self._restart_auto_lock_timer()

    def set_auto_lock_enabled(self, enabled: bool) -> None:
        self._auto_lock_enabled = enabled
        if enabled:
            self._start_auto_lock_timer()
        else:
            self._cancel_auto_lock()

    def _start_auto_lock_timer(self) -> None:
        if not self._auto_lock_enabled:
            return
        self._cancel_auto_lock()
        self._auto_lock_timer = threading.Timer(
            AUTO_LOCK_DELAY, self._auto_lock_triggered
        )
        self._auto_lock_timer.daemon = True
        self._auto_lock_timer.start()

    def _restart_auto_lock_timer(self) -> None:
        if self._auto_lock_enabled and self._db.is_unlocked:
            self._start_auto_lock_timer()

    def _cancel_auto_lock(self) -> None:
        if self._auto_lock_timer is not None:
            self._auto_lock_timer.cancel()
            self._auto_lock_timer = None

    def _auto_lock_triggered(self) -> None:
        if self._db.is_unlocked:
            self.lock()

    # ── entries ───────────────────────────────────────────────────────────────

    def get_all_entries(self) -> list[dict]:
        self._reset_activity()
        return self._db.get_all_entries()

    def get_entry(self, entry_id: int) -> dict | None:
        self._reset_activity()
        return self._db.get_entry(entry_id)

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
    ) -> int:
        self._reset_activity()
        return self._db.add_entry(title, username, password, url, notes)

    def update_entry(
        self,
        entry_id: int,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
    ) -> bool:
        self._reset_activity()
        return self._db.update_entry(
            entry_id, title, username, password, url, notes
        )

    def delete_entry(self, entry_id: int) -> bool:
        self._reset_activity()
        return self._db.delete_entry(entry_id)

    # ── password generator ────────────────────────────────────────────────────

    @staticmethod
    def generate_password(
        length: int = 20,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        return generate_password(length, use_upper, use_digits, use_symbols)

    # ── clipboard ─────────────────────────────────────────────────────────────

    def copy_password_to_clipboard(self, password: str) -> bool:
        """Copy *password* to the clipboard and schedule an auto-clear.

        Returns *True* if the clipboard operation succeeded.
        """
        self._reset_activity()
        if not _PYPERCLIP_AVAILABLE:
            return False
        try:
            pyperclip.copy(password)
            self._schedule_clipboard_clear()
            return True
        except Exception:
            return False

    def _schedule_clipboard_clear(self) -> None:
        self._cancel_clipboard_timer()
        self._clipboard_timer = threading.Timer(
            CLIPBOARD_CLEAR_DELAY, self._clear_clipboard
        )
        self._clipboard_timer.daemon = True
        self._clipboard_timer.start()

    def _cancel_clipboard_timer(self) -> None:
        if self._clipboard_timer is not None:
            self._clipboard_timer.cancel()
            self._clipboard_timer = None

    @staticmethod
    def _clear_clipboard() -> None:
        if _PYPERCLIP_AVAILABLE:
            try:
                pyperclip.copy("")
            except Exception:
                pass

    # ── launch & auto-type ────────────────────────────────────────────────────

    def launch_and_autotype(
        self,
        url: str,
        username: str,
        password: str,
        wait_seconds: int = AUTO_TYPE_WAIT,
    ) -> None:
        """Open *url* in the default browser, then auto-type credentials.

        The operation runs in a background thread so the GUI stays responsive.
        """
        thread = threading.Thread(
            target=self._autotype_worker,
            args=(url, username, password, wait_seconds),
            daemon=True,
        )
        thread.start()

    def _autotype_worker(
        self,
        url: str,
        username: str,
        password: str,
        wait_seconds: int,
    ) -> None:
        webbrowser.open(url)
        time.sleep(wait_seconds)

        if not _PYAUTOGUI_AVAILABLE:
            return

        try:
            pyautogui.typewrite(username, interval=0.05)
            pyautogui.press("tab")
            pyautogui.typewrite(password, interval=0.05)
            pyautogui.press("enter")
        except Exception:
            pass

    def autofill_credentials(
        self,
        username: str,
        password: str,
        wait_seconds: int = 1,
    ) -> None:
        """Auto-type username and password into the active field.

        Waits a short delay before typing to allow the user to click on
        the target field.
        """
        thread = threading.Thread(
            target=self._autofill_worker,
            args=(username, password, wait_seconds),
            daemon=True,
        )
        thread.start()

    def _autofill_worker(
        self,
        username: str,
        password: str,
        wait_seconds: int,
    ) -> None:
        time.sleep(wait_seconds)

        if not _PYAUTOGUI_AVAILABLE:
            return

        try:
            pyautogui.typewrite(username, interval=0.05)
            pyautogui.press("tab")
            pyautogui.typewrite(password, interval=0.05)
        except Exception:
            pass
