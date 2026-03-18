"""
Phase 3 – Graphical User Interface (GUI).

Built with customtkinter for a modern, clean look.

Screens / windows
-----------------
  LoginFrame       – Master-password entry on first run (setup) and on
                     subsequent launches (unlock).
  MainFrame        – Dashboard with the credential table and action buttons.
  EntryDialog      – Add/Edit entry modal dialog.
  ChangePasswordDialog – Change master password modal dialog.

The ``App`` class wires everything together and hosts the ``PasswordManagerController``.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

import customtkinter as ctk

from src.controller import (
    PasswordManagerController,
    AUTO_LOCK_DELAY,
    CLIPBOARD_CLEAR_DELAY,
)

# ──────────────────────────────────────────────────────────────────────────────
# Appearance
# ──────────────────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

WINDOW_TITLE = "Desktop Password Manager"
WINDOW_MIN_W = 900
WINDOW_MIN_H = 600

# Palette shortcuts
_COLOR_DANGER = "#c0392b"
_COLOR_SUCCESS = "#27ae60"
_COLOR_ACCENT = "#2980b9"
_COLOR_BG_DARK = "#1a1a2e"


# ──────────────────────────────────────────────────────────────────────────────
# Helper: label + entry pair
# ──────────────────────────────────────────────────────────────────────────────

def _labelled_entry(
    parent,
    label: str,
    row: int,
    show: str = "",
    initial_value: str = "",
) -> ctk.CTkEntry:
    ctk.CTkLabel(parent, text=label, anchor="w").grid(
        row=row, column=0, sticky="w", padx=(0, 8), pady=4
    )
    entry = ctk.CTkEntry(parent, show=show, width=320)
    entry.grid(row=row, column=1, sticky="ew", pady=4)
    if initial_value:
        entry.insert(0, initial_value)
    return entry


# ──────────────────────────────────────────────────────────────────────────────
# LoginFrame
# ──────────────────────────────────────────────────────────────────────────────

class LoginFrame(ctk.CTkFrame):
    """Login / first-run setup screen."""

    def __init__(self, master: "App") -> None:
        super().__init__(master, fg_color="transparent")
        self._app = master
        self._build_ui()

    def _build_ui(self) -> None:
        is_first_run = self._app.controller.is_first_run()

        # Centre the card
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        card = ctk.CTkFrame(self, width=420, corner_radius=16)
        card.grid(row=0, column=0)
        card.columnconfigure(1, weight=1)

        title_text = "Create Vault" if is_first_run else "Unlock Vault"
        ctk.CTkLabel(
            card,
            text=f"🔐  {title_text}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, columnspan=2, pady=(28, 16), padx=32)

        if is_first_run:
            ctk.CTkLabel(
                card,
                text="No vault found.  Set a master password to create one.",
                wraplength=360,
                text_color="gray",
            ).grid(row=1, column=0, columnspan=2, padx=32, pady=(0, 12))

        self._pw_entry = _labelled_entry(card, "Master Password", row=2, show="•")
        self._pw_entry.grid_configure(padx=(0, 32))

        if is_first_run:
            self._confirm_entry = _labelled_entry(
                card, "Confirm Password", row=3, show="•"
            )
            self._confirm_entry.grid_configure(padx=(0, 32))
            btn_row = 4
        else:
            self._confirm_entry = None
            btn_row = 3

        self._status_label = ctk.CTkLabel(
            card, text="", text_color=_COLOR_DANGER, wraplength=360
        )
        self._status_label.grid(
            row=btn_row, column=0, columnspan=2, padx=32, pady=4
        )

        btn_text = "Create Vault" if is_first_run else "Unlock"
        ctk.CTkButton(
            card,
            text=btn_text,
            command=self._on_submit,
            fg_color=_COLOR_ACCENT,
            hover_color="#1a6496",
        ).grid(
            row=btn_row + 1,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=32,
            pady=(8, 28),
        )

        # Allow pressing Enter to submit
        self._pw_entry.bind("<Return>", lambda _e: self._on_submit())
        if self._confirm_entry:
            self._confirm_entry.bind("<Return>", lambda _e: self._on_submit())

        # Give focus to the password field
        self.after(100, self._pw_entry.focus_set)

    def _on_submit(self) -> None:
        pw = self._pw_entry.get()
        if not pw:
            self._set_status("Password cannot be empty.")
            return

        if self._app.controller.is_first_run():
            confirm = self._confirm_entry.get() if self._confirm_entry else ""
            if pw != confirm:
                self._set_status("Passwords do not match.")
                return
            if len(pw) < 8:
                self._set_status("Password must be at least 8 characters.")
                return
            self._app.controller.create_vault(pw)
            self._clear_fields()
            self._app.show_main()
        else:
            if self._app.controller.unlock(pw):
                self._clear_fields()
                self._app.show_main()
            else:
                self._set_status("Incorrect password.  Please try again.")
                self._pw_entry.delete(0, "end")

    def _set_status(self, msg: str) -> None:
        self._status_label.configure(text=msg)

    def _clear_fields(self) -> None:
        self._pw_entry.delete(0, "end")
        if self._confirm_entry:
            self._confirm_entry.delete(0, "end")


# ──────────────────────────────────────────────────────────────────────────────
# EntryDialog
# ──────────────────────────────────────────────────────────────────────────────

class EntryDialog(ctk.CTkToplevel):
    """Modal dialog for adding or editing a credential entry."""

    def __init__(
        self,
        master: "App",
        entry: dict | None = None,
    ) -> None:
        super().__init__(master)
        self._app = master
        self._entry = entry
        self.result: dict | None = None

        title = "Edit Entry" if entry else "Add Entry"
        self.title(title)
        self.geometry("500x520")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        e = self._entry or {}

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=24, pady=16)
        frame.columnconfigure(1, weight=1)

        self._title_e = _labelled_entry(
            frame, "Title *", 0, initial_value=e.get("title", "")
        )
        self._user_e = _labelled_entry(
            frame, "Username *", 1, initial_value=e.get("username", "")
        )
        self._pw_e = _labelled_entry(
            frame, "Password *", 2, show="•", initial_value=e.get("password", "")
        )

        # Password visibility toggle + generator
        pw_btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        pw_btn_frame.grid(row=3, column=1, sticky="w", pady=2)

        self._show_pw = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            pw_btn_frame,
            text="Show",
            variable=self._show_pw,
            command=self._toggle_pw_visibility,
            width=60,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            pw_btn_frame,
            text="⚙ Generate",
            width=110,
            command=self._generate_password,
            fg_color=_COLOR_SUCCESS,
            hover_color="#1e8449",
        ).pack(side="left")

        self._url_e = _labelled_entry(
            frame, "URL", 4, initial_value=e.get("url", "")
        )

        ctk.CTkLabel(frame, text="Notes", anchor="w").grid(
            row=5, column=0, sticky="nw", padx=(0, 8), pady=4
        )
        self._notes_box = ctk.CTkTextbox(frame, height=90, width=320)
        self._notes_box.grid(row=5, column=1, sticky="ew", pady=4)
        if e.get("notes"):
            self._notes_box.insert("1.0", e["notes"])

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        btn_frame.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            btn_frame, text="Save", command=self._on_save, width=120
        ).grid(row=0, column=0, padx=4)
        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=self.destroy,
            width=120,
            fg_color="gray40",
            hover_color="gray30",
        ).grid(row=0, column=1, padx=4)

    def _toggle_pw_visibility(self) -> None:
        char = "" if self._show_pw.get() else "•"
        self._pw_e.configure(show=char)

    def _generate_password(self) -> None:
        pw = self._app.controller.generate_password()
        self._pw_e.delete(0, "end")
        self._pw_e.insert(0, pw)
        # Show the generated password automatically
        self._show_pw.set(True)
        self._pw_e.configure(show="")

    def _on_save(self) -> None:
        title = self._title_e.get().strip()
        username = self._user_e.get().strip()
        password = self._pw_e.get()
        url = self._url_e.get().strip()
        notes = self._notes_box.get("1.0", "end").strip()

        if not title:
            messagebox.showwarning("Validation", "Title is required.", parent=self)
            return
        if not username:
            messagebox.showwarning(
                "Validation", "Username is required.", parent=self
            )
            return
        if not password:
            messagebox.showwarning(
                "Validation", "Password is required.", parent=self
            )
            return

        self.result = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }
        self.destroy()


# ──────────────────────────────────────────────────────────────────────────────
# ChangePasswordDialog
# ──────────────────────────────────────────────────────────────────────────────

class ChangePasswordDialog(ctk.CTkToplevel):
    """Modal dialog for changing the master password."""

    def __init__(self, master: "App") -> None:
        super().__init__(master)
        self._app = master
        self.title("Change Master Password")
        self.geometry("420x320")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self._build_ui()

    def _build_ui(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=24, pady=16)
        frame.columnconfigure(1, weight=1)

        self._cur_pw = _labelled_entry(frame, "Current Password", 0, show="•")
        self._new_pw = _labelled_entry(frame, "New Password", 1, show="•")
        self._confirm_pw = _labelled_entry(frame, "Confirm New Password", 2, show="•")

        self._status = ctk.CTkLabel(
            frame, text="", text_color=_COLOR_DANGER, wraplength=360
        )
        self._status.grid(row=3, column=0, columnspan=2, pady=4)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        btn_frame.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(btn_frame, text="Change", command=self._on_change, width=120).grid(
            row=0, column=0, padx=4
        )
        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=self.destroy,
            width=120,
            fg_color="gray40",
            hover_color="gray30",
        ).grid(row=0, column=1, padx=4)

    def _on_change(self) -> None:
        cur = self._cur_pw.get()
        new = self._new_pw.get()
        confirm = self._confirm_pw.get()

        if not cur or not new or not confirm:
            self._status.configure(text="All fields are required.")
            return
        if new != confirm:
            self._status.configure(text="New passwords do not match.")
            return
        if len(new) < 8:
            self._status.configure(text="Password must be at least 8 characters.")
            return

        success = self._app.controller.change_master_password(cur, new)
        if success:
            messagebox.showinfo(
                "Success", "Master password changed successfully.", parent=self
            )
            self.destroy()
        else:
            self._status.configure(text="Current password is incorrect.")


# ──────────────────────────────────────────────────────────────────────────────
# MainFrame
# ──────────────────────────────────────────────────────────────────────────────

class MainFrame(ctk.CTkFrame):
    """Main dashboard – credential list + action buttons."""

    # Table column configuration: (heading, key, width, stretch)
    _COLUMNS = [
        ("Title", "title", 180, True),
        ("Username", "username", 180, True),
        ("Password", "password", 120, False),
        ("URL", "url", 200, True),
    ]

    def __init__(self, master: "App") -> None:
        super().__init__(master, fg_color="transparent")
        self._app = master
        self._entries: list[dict] = []
        self._selected_id: int | None = None
        self._pw_visible: set[int] = set()
        self._build_ui()
        self.refresh()

    # ── layout ────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        self._build_toolbar()
        self._build_table()
        self._build_statusbar()
        
        # Give focus to table instead of search box to prevent accidental text input
        # when returning from launched browser window
        self.after(100, self._tree.focus_set)

    def _build_toolbar(self) -> None:
        toolbar = ctk.CTkFrame(self, height=50, corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        toolbar.columnconfigure(6, weight=1)  # push lock to the right

        btn_cfg = {"width": 100, "height": 34}

        ctk.CTkButton(
            toolbar, text="+ Add", command=self._on_add,
            fg_color=_COLOR_SUCCESS, hover_color="#1e8449", **btn_cfg
        ).grid(row=0, column=0, padx=6, pady=8)

        ctk.CTkButton(
            toolbar, text="✏ Edit", command=self._on_edit, **btn_cfg
        ).grid(row=0, column=1, padx=4, pady=8)

        ctk.CTkButton(
            toolbar, text="🗑 Delete", command=self._on_delete,
            fg_color=_COLOR_DANGER, hover_color="#922b21", **btn_cfg
        ).grid(row=0, column=2, padx=4, pady=8)

        ctk.CTkButton(
            toolbar, text="📋 Copy PW", command=self._on_copy_password, **btn_cfg
        ).grid(row=0, column=3, padx=4, pady=8)

        ctk.CTkButton(
            toolbar, text="� Autofill", command=self._on_autofill,
            fg_color="#16a085", hover_color="#117a65", **btn_cfg
        ).grid(row=0, column=4, padx=4, pady=8)

        ctk.CTkButton(
            toolbar, text="🚀 Launch", command=self._on_launch,
            fg_color="#8e44ad", hover_color="#6c3483", **btn_cfg
        ).grid(row=0, column=5, padx=4, pady=8)

        # Search box
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._on_search())
        search_entry = ctk.CTkEntry(
            toolbar,
            textvariable=self._search_var,
            placeholder_text="🔍  Search …",
            width=200,
        )
        search_entry.grid(row=0, column=6, padx=8, pady=8, sticky="e")

        # Lock + settings
        ctk.CTkButton(
            toolbar, text="🔒 Lock", command=self._app.lock,
            fg_color="gray40", hover_color="gray30", **btn_cfg
        ).grid(row=0, column=7, padx=(4, 6), pady=8)

        ctk.CTkButton(
            toolbar, text="⚙", command=self._open_settings,
            fg_color="gray40", hover_color="gray30", width=40, height=34
        ).grid(row=0, column=8, padx=(0, 8), pady=8)

    def _build_table(self) -> None:
        import tkinter.ttk as ttk

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Vault.Treeview",
            background="#2b2b3b",
            foreground="white",
            rowheight=28,
            fieldbackground="#2b2b3b",
            bordercolor="#444",
            borderwidth=0,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background="#1e1e2e",
            foreground="white",
            relief="flat",
        )
        style.map(
            "Vault.Treeview",
            background=[("selected", "#2980b9")],
            foreground=[("selected", "white")],
        )

        table_frame = ctk.CTkFrame(self, corner_radius=8)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = [col[0] for col in self._COLUMNS]
        self._tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            style="Vault.Treeview",
            selectmode="browse",
        )

        for heading, _key, width, stretch in self._COLUMNS:
            self._tree.heading(heading, text=heading)
            self._tree.column(heading, width=width, stretch=stretch)

        scrollbar = ctk.CTkScrollbar(
            table_frame, command=self._tree.yview, width=14
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _e: self._on_edit())

    def _build_statusbar(self) -> None:
        self._status_var = tk.StringVar(value="")
        status_bar = ctk.CTkLabel(
            self,
            textvariable=self._status_var,
            anchor="w",
            text_color="gray",
            font=ctk.CTkFont(size=11),
        )
        status_bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(2, 6))

    # ── data ──────────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload all entries from the vault and repopulate the table."""
        self._entries = self._app.controller.get_all_entries()
        self._pw_visible.clear()
        self._selected_id = None
        self._populate_table(self._entries)
        self._update_status(f"{len(self._entries)} entries")

    def _populate_table(self, entries: list[dict]) -> None:
        self._tree.delete(*self._tree.get_children())
        for e in entries:
            self._tree.insert(
                "",
                "end",
                iid=str(e["id"]),
                values=(
                    e["title"],
                    e["username"],
                    "••••••••",
                    e["url"],
                ),
            )

    def _on_search(self) -> None:
        query = self._search_var.get().lower().strip()
        if not query:
            self._populate_table(self._entries)
            return
        filtered = [
            e
            for e in self._entries
            if query in e["title"].lower()
            or query in e["username"].lower()
            or query in e["url"].lower()
        ]
        self._populate_table(filtered)

    def _selected_entry(self) -> dict | None:
        sel = self._tree.selection()
        if not sel:
            return None
        entry_id = int(sel[0])
        return next((e for e in self._entries if e["id"] == entry_id), None)

    def _on_select(self, _event=None) -> None:
        entry = self._selected_entry()
        if entry:
            self._selected_id = entry["id"]

    # ── actions ───────────────────────────────────────────────────────────────

    def _on_add(self) -> None:
        self._app.controller.record_activity()
        dialog = EntryDialog(self._app)
        self._app.wait_window(dialog)
        if dialog.result:
            self._app.controller.add_entry(**dialog.result)
            self.refresh()
            self._update_status("Entry added.")

    def _on_edit(self) -> None:
        self._app.controller.record_activity()
        entry = self._selected_entry()
        if not entry:
            messagebox.showinfo("Edit", "Please select an entry to edit.")
            return
        dialog = EntryDialog(self._app, entry=entry)
        self._app.wait_window(dialog)
        if dialog.result:
            self._app.controller.update_entry(entry["id"], **dialog.result)
            self.refresh()
            self._update_status("Entry updated.")

    def _on_delete(self) -> None:
        self._app.controller.record_activity()
        entry = self._selected_entry()
        if not entry:
            messagebox.showinfo("Delete", "Please select an entry to delete.")
            return
        if messagebox.askyesno(
            "Confirm Delete",
            f"Delete '{entry['title']}'?  This cannot be undone.",
        ):
            self._app.controller.delete_entry(entry["id"])
            self.refresh()
            self._update_status("Entry deleted.")

    def _on_copy_password(self) -> None:
        self._app.controller.record_activity()
        entry = self._selected_entry()
        if not entry:
            messagebox.showinfo("Copy", "Please select an entry first.")
            return
        success = self._app.controller.copy_password_to_clipboard(
            entry["password"]
        )
        if success:
            self._update_status(
                f"Password copied.  Clipboard will be cleared in "
                f"{CLIPBOARD_CLEAR_DELAY} seconds."
            )
        else:
            messagebox.showwarning(
                "Clipboard",
                "Could not access the clipboard.  "
                "Make sure 'pyperclip' and a clipboard tool are installed.",
            )

    def _on_autofill(self) -> None:
        self._app.controller.record_activity()
        entry = self._selected_entry()
        if not entry:
            messagebox.showinfo("Autofill", "Please select an entry first.")
            return
        
        # Release focus from search box and give it to table to prevent
        # autofill from typing into search box
        self._tree.focus_set()
        
        self._app.controller.autofill_credentials(
            entry["username"], entry["password"]
        )
        self._update_status(
            "Autofill ready – click on the target field within 1 second."
        )

    def _on_launch(self) -> None:
        self._app.controller.record_activity()
        entry = self._selected_entry()
        if not entry:
            messagebox.showinfo("Launch", "Please select an entry first.")
            return
        if not entry.get("url"):
            messagebox.showwarning("Launch", "This entry has no URL.")
            return
        
        # Set focus to table to prevent accidental text input to search box
        # if user returns to app window before autotype completes
        self._tree.focus_set()
        
        self._app.controller.launch_and_autotype(
            entry["url"], entry["username"], entry["password"]
        )
        self._update_status(
            f"Launched {entry['url']} – auto-type will run in ~4 seconds."
        )

    def _open_settings(self) -> None:
        self._app.controller.record_activity()
        ChangePasswordDialog(self._app)

    def _update_status(self, msg: str) -> None:
        self._status_var.set(msg)


# ──────────────────────────────────────────────────────────────────────────────
# App – root window
# ──────────────────────────────────────────────────────────────────────────────

class App(ctk.CTk):
    """Root application window."""

    def __init__(self, db_path: Path | None = None) -> None:
        super().__init__()
        self.title(WINDOW_TITLE)
        self.minsize(WINDOW_MIN_W, WINDOW_MIN_H)
        self.geometry(f"{WINDOW_MIN_W}x{WINDOW_MIN_H}")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Controller
        kwargs = {"db_path": db_path} if db_path else {}
        self.controller = PasswordManagerController(**kwargs)
        self.controller.set_lock_callback(self._on_locked)
        self.controller.startup()

        self._current_frame: ctk.CTkFrame | None = None
        self.show_login()

        # Bind any key/click to record activity
        self.bind_all("<Key>", lambda _e: self.controller.record_activity())
        self.bind_all("<Button>", lambda _e: self.controller.record_activity())

    # ── frame switching ───────────────────────────────────────────────────────

    def _switch_frame(self, frame: ctk.CTkFrame) -> None:
        if self._current_frame is not None:
            self._current_frame.destroy()
        self._current_frame = frame
        frame.pack(fill="both", expand=True)

    def show_login(self) -> None:
        self._switch_frame(LoginFrame(self))

    def show_main(self) -> None:
        self._switch_frame(MainFrame(self))

    def lock(self) -> None:
        """Lock the vault and return to the login screen."""
        self.controller.lock()

    # ── callbacks ─────────────────────────────────────────────────────────────

    def _on_locked(self) -> None:
        """Called by the controller when the vault is auto-locked."""
        # Must run on the main thread
        self.after(0, self.show_login)

    def _on_close(self) -> None:
        self.controller.shutdown()
        self.destroy()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point (when this module is run directly – not the normal entry point)
# ──────────────────────────────────────────────────────────────────────────────

def run_app(db_path: Path | None = None) -> None:
    app = App(db_path=db_path)
    app.mainloop()


if __name__ == "__main__":
    run_app()
