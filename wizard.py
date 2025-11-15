import json
import os
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from theme import (
    PROXMOX_ACCENT,
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
)


class AccountStore:
    def __init__(self) -> None:
        self.config_dir = Path.home() / ".config" / "Proxmox-LDC"
        self.accounts_dir = self.config_dir / "Accounts"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.accounts_dir.mkdir(parents=True, exist_ok=True)

    def account_path(self, username: str) -> Path:
        return self.accounts_dir / username

    def credentials_file(self, username: str) -> Path:
        return self.account_path(username) / "account.json"

    def account_exists(self, username: str) -> bool:
        return self.credentials_file(username).exists()

    def list_accounts(self) -> list[str]:
        return [
            item.name
            for item in self.accounts_dir.iterdir()
            if item.is_dir() and (item / "account.json").exists()
        ]

    def load_account(self, username: str) -> dict | None:
        try:
            with self.credentials_file(username).open("r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            return None

    def get_default_account(self) -> dict | None:
        accounts = self.list_accounts()
        if not accounts:
            return None
        return self.load_account(accounts[0])

    def save_account(self, account_data: dict) -> dict:
        username = account_data["username"]
        account_dir = self.account_path(username)
        account_dir.mkdir(parents=True, exist_ok=True)

        with self.credentials_file(username).open("w", encoding="utf-8") as file:
            json.dump(account_data, file, indent=2)

        return account_data


def hash_password(password: str, salt: str) -> str:
    """Simple salted hash using sha256. Replace with stronger hashing later."""
    import hashlib

    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


def show_completion_dialog(parent: tk.Widget, message: str, on_close) -> None:
    top = tk.Toplevel(parent)
    top.title("Setup complete")
    top.configure(bg=PROXMOX_DARK)
    top.resizable(False, False)
    top.transient(parent.winfo_toplevel())
    top.grab_set()

    width, height = 420, 220
    root = parent.winfo_toplevel()
    root.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() // 2) - (width // 2)
    y = root.winfo_rooty() + (root.winfo_height() // 2) - (height // 2)
    top.geometry(f"{width}x{height}+{x}+{y}")

    container = ttk.Frame(top, style="Wizard.Card.TFrame")
    container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    heading = ttk.Label(
        container,
        text="You're all set!",
        style="WizardHeader.TLabel",
    )
    heading.pack(anchor=tk.W, pady=(0, 6))

    body = ttk.Label(
        container,
        text=message,
        style="Wizard.SubHeader.TLabel",
        wraplength=360,
    )
    body.pack(anchor=tk.W, pady=(0, 20))

    action_btn = ttk.Button(
        container,
        text="Continue",
        style="Wizard.TButton",
        command=lambda: close_dialog(),
    )
    action_btn.pack(anchor=tk.E)

    def close_dialog() -> None:
        top.grab_release()
        top.destroy()
        if callable(on_close):
            on_close()

    top.protocol("WM_DELETE_WINDOW", close_dialog)
    action_btn.focus_set()


class SetupWizard(tk.Frame):
    def __init__(self, master: tk.Tk, store: AccountStore, on_complete) -> None:
        super().__init__(master, bg=PROXMOX_DARK)
        self.store = store
        self.on_complete = on_complete
        self.current_step = 0
        self.account_info: dict[str, str] = {}

        self._configure_style()
        self._create_variables()
        self._build_ui()
        self._show_step(0)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "Wizard.TFrame",
            padding=20,
            background=PROXMOX_DARK,
        )
        style.configure(
            "Wizard.Card.TFrame",
            padding=25,
            background=PROXMOX_MEDIUM,
            relief="flat",
        )
        style.configure(
            "Wizard.TLabel",
            font=("Segoe UI", 11),
            foreground=PROXMOX_LIGHT,
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "WizardHeader.TLabel",
            font=("Segoe UI", 18, "bold"),
            foreground=PROXMOX_LIGHT,
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "Wizard.SubHeader.TLabel",
            font=("Segoe UI", 12),
            foreground="#b0b6bf",
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "Wizard.TButton",
            font=("Segoe UI", 11, "bold"),
            background=PROXMOX_ORANGE,
            foreground="white",
            padding=10,
            borderwidth=0,
        )
        style.map(
            "Wizard.TButton",
            background=[("active", "#ff8126"), ("disabled", "#666")],
        )
        style.configure(
            "Wizard.Secondary.TButton",
            font=("Segoe UI", 11),
            background=PROXMOX_MEDIUM,
            foreground=PROXMOX_LIGHT,
            bordercolor=PROXMOX_LIGHT,
            padding=10,
        )
        style.map(
            "Wizard.Secondary.TButton",
            background=[("active", "#353c45")],
        )
        style.configure(
            "Wizard.Horizontal.TSeparator",
            background="#3c434e",
            foreground="#3c434e",
        )

        # Entry styling
        style.configure(
            "Wizard.TEntry",
            fieldbackground="#1f242b",
            background="#1f242b",
            foreground=PROXMOX_LIGHT,
            bordercolor="#363c45",
            insertcolor=PROXMOX_LIGHT,
            padding=8,
        )

        self.configure(bg=PROXMOX_DARK)

    def _create_variables(self) -> None:
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.proxmox_host_var = tk.StringVar()
        self.proxmox_user_var = tk.StringVar()
        self.proxmox_password_var = tk.StringVar()

    def _build_ui(self) -> None:
        header_wrapper = ttk.Frame(self, style="Wizard.TFrame")
        header_wrapper.pack(fill=tk.X, padx=30, pady=(20, 10))

        title = ttk.Label(
            header_wrapper,
            text="Proxmox-LDC Setup",
            font=("Segoe UI", 24, "bold"),
            foreground=PROXMOX_ORANGE,
            background=PROXMOX_DARK,
        )
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            header_wrapper,
            text="Create your desktop account and connect to Proxmox.",
            font=("Segoe UI", 12),
            foreground="#b0b6bf",
            background=PROXMOX_DARK,
        )
        subtitle.pack(anchor=tk.W, pady=(4, 0))

        content_frame = ttk.Frame(self, style="Wizard.TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 10))

        self.card = ttk.Frame(content_frame, style="Wizard.Card.TFrame")
        self.card.pack(fill=tk.BOTH, expand=True)

        self.container = ttk.Frame(self.card, style="Wizard.Card.TFrame")
        self.container.pack(fill=tk.BOTH, expand=True)

        self.steps = [self._build_account_step(), self._build_proxmox_step()]

        nav_frame = ttk.Frame(self.card, style="Wizard.Card.TFrame")
        nav_frame.pack(fill=tk.X, pady=(20, 0))

        self.step_indicator = ttk.Label(
            nav_frame,
            text="Step 1 of 2",
            style="Wizard.SubHeader.TLabel",
            background=PROXMOX_MEDIUM,
        )
        self.step_indicator.pack(side=tk.LEFT)

        button_group = ttk.Frame(nav_frame, style="Wizard.Card.TFrame")
        button_group.pack(side=tk.RIGHT)

        self.back_button = ttk.Button(
            button_group,
            text="Back",
            command=self._previous_step,
            style="Wizard.Secondary.TButton",
        )
        self.back_button.pack(side=tk.LEFT, padx=(0, 10))

        self.next_button = ttk.Button(
            button_group,
            text="Next",
            command=self._next_step,
            style="Wizard.TButton",
        )
        self.next_button.pack(side=tk.LEFT)

    def _build_account_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Create your local account", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Secure access to this desktop client with a username and password.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self._add_labeled_entry(frame, "Username", self.username_var)
        self._add_labeled_entry(
            frame, "Password", self.password_var, show="*"
        )
        self._add_labeled_entry(
            frame, "Confirm Password", self.confirm_password_var, show="*"
        )

        return frame

    def _build_proxmox_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Proxmox API credentials", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Provide connection details for your Proxmox host.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self._add_labeled_entry(
            frame,
            "Proxmox Host/IP (e.g., https://192.168.1.10:8006)",
            self.proxmox_host_var,
        )
        self._add_labeled_entry(
            frame,
            "Proxmox Username (e.g., root@pam)",
            self.proxmox_user_var,
        )
        self._add_labeled_entry(
            frame,
            "Proxmox Password",
            self.proxmox_password_var,
            show="*",
        )

        return frame

    def _add_labeled_entry(
        self,
        parent: ttk.Frame,
        label_text: str,
        variable: tk.StringVar,
        show: str | None = None,
    ) -> None:
        label = ttk.Label(parent, text=label_text, style="Wizard.TLabel")
        label.pack(anchor=tk.W, pady=(5, 2))
        entry = ttk.Entry(parent, textvariable=variable, show=show or "", style="Wizard.TEntry")
        entry.pack(fill=tk.X, pady=(0, 5))

    def _show_step(self, index: int) -> None:
        for frame in self.steps:
            frame.pack_forget()
        self.steps[index].pack(fill=tk.BOTH, expand=True)
        self.current_step = index
        self.back_button["state"] = tk.NORMAL if index > 0 else tk.DISABLED
        self.next_button["text"] = "Finish" if index == len(self.steps) - 1 else "Next"
        self.step_indicator.config(text=f"Step {index + 1} of {len(self.steps)}")

    def _next_step(self) -> None:
        if not self._validate_current_step():
            return

        if self.current_step == len(self.steps) - 1:
            self._complete_wizard()
        else:
            self._show_step(self.current_step + 1)

    def _previous_step(self) -> None:
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    def _validate_current_step(self) -> bool:
        if self.current_step == 0:
            username = self.username_var.get().strip()
            password = self.password_var.get()
            confirm_password = self.confirm_password_var.get()

            if not username or not password:
                messagebox.showerror("Missing information", "Username and password are required.")
                return False

            if password != confirm_password:
                messagebox.showerror("Password mismatch", "Passwords do not match.")
                return False

            if self.store.account_exists(username):
                messagebox.showerror("Account exists", "This username is already in use.")
                return False

        elif self.current_step == 1:
            host = self.proxmox_host_var.get().strip()
            user = self.proxmox_user_var.get().strip()
            password = self.proxmox_password_var.get()

            if not host or not user or not password:
                messagebox.showerror("Missing information", "All Proxmox fields are required.")
                return False

        return True

    def _complete_wizard(self) -> None:
        username = self.username_var.get().strip()
        password = self.password_var.get()
        salt = os.urandom(16).hex()

        account_payload = {
            "username": username,
            "password": {
                "salt": salt,
                "hash": hash_password(password, salt),
            },
            "proxmox": {
                "host": self.proxmox_host_var.get().strip(),
                "username": self.proxmox_user_var.get().strip(),
                "password": self.proxmox_password_var.get(),
            },
        }

        saved = self.store.save_account(account_payload)

        def finalize() -> None:
            self.destroy()
            if callable(self.on_complete):
                self.on_complete(saved)

        show_completion_dialog(
            self,
            "Your local account and Proxmox API credentials have been stored securely.",
            finalize,
        )


__all__ = ["AccountStore", "SetupWizard"]

