import json
import os
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any

from trust import fetch_server_certificate, prompt_trust_dialog

from theme import (
    PROXMOX_ACCENT,
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
)


class AccountStore:
    def __init__(self, config_dir: Path | None = None) -> None:
        if config_dir is None:
            # Try to get custom config dir from a global preference file
            # This is a simple approach - in a real app you might want a more robust solution
            default_config = Path.home() / ".config" / "Proxmox-LDC"
            pref_file = default_config / "preferences.json"
            if pref_file.exists():
                try:
                    with pref_file.open("r", encoding="utf-8") as f:
                        prefs = json.load(f)
                        custom_dir = prefs.get("config_dir")
                        if custom_dir:
                            config_dir = Path(custom_dir)
                except Exception:
                    pass
            
            if config_dir is None:
                config_dir = default_config
        
        self.config_dir = Path(config_dir)
        self.accounts_dir = self.config_dir / "Accounts"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.accounts_dir.mkdir(parents=True, exist_ok=True)

    def account_path(self, username: str) -> Path:
        return self.accounts_dir / username

    def credentials_file(self, username: str) -> Path:
        return self.account_path(username) / "account.json"

    def trusted_cert_file(self, username: str) -> Path:
        return self.account_path(username) / "trusted_server.pem"

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

        data = json.loads(json.dumps(account_data))

        with self.credentials_file(username).open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)

        return account_data

    def save_trusted_cert(self, username: str, pem_data: str) -> str:
        cert_path = self.trusted_cert_file(username)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(pem_data, encoding="utf-8")
        return str(cert_path)


def hash_password(password: str, salt: str) -> str:
    """Simple salted hash using sha256. Replace with stronger hashing later."""
    import hashlib

    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


def _styled_error(parent: tk.Widget, title: str, message: str) -> None:
    """Show a styled error dialog matching the app theme."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 250
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 100
    dialog.geometry(f"500x180+{x}+{y}")

    tk.Label(
        dialog,
        text=title,
        font=("Segoe UI", 14, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
        anchor="w",
    ).pack(fill=tk.X, padx=24, pady=(20, 6))

    tk.Label(
        dialog,
        text=message,
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        wraplength=450,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=24, pady=(0, 16))

    actions = tk.Frame(dialog, bg=PROXMOX_DARK)
    actions.pack(fill=tk.X, padx=24, pady=(0, 20))

    tk.Button(
        actions,
        text="Close",
        command=dialog.destroy,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=18,
        pady=8,
    ).pack(side=tk.RIGHT)

    dialog.wait_window()


def _styled_info(parent: tk.Widget, title: str, message: str) -> None:
    """Show a styled info dialog matching the app theme."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 250
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 100
    dialog.geometry(f"500x180+{x}+{y}")

    tk.Label(
        dialog,
        text=title,
        font=("Segoe UI", 14, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
        anchor="w",
    ).pack(fill=tk.X, padx=24, pady=(20, 6))

    tk.Label(
        dialog,
        text=message,
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        wraplength=450,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=24, pady=(0, 16))

    actions = tk.Frame(dialog, bg=PROXMOX_DARK)
    actions.pack(fill=tk.X, padx=24, pady=(0, 20))

    tk.Button(
        actions,
        text="OK",
        command=dialog.destroy,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=18,
        pady=8,
    ).pack(side=tk.RIGHT)

    dialog.wait_window()


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
        self.servers: list[dict[str, Any]] = []  # Store multiple server configs

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
        self.current_server_index = 0

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

        header_frame = ttk.Frame(frame, style="Wizard.Card.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 12))
        
        ttk.Label(header_frame, text="Proxmox API credentials", style="WizardHeader.TLabel").pack(
            side=tk.LEFT, anchor=tk.W
        )
        
        self.server_count_label = ttk.Label(
            header_frame,
            text="",
            style="Wizard.SubHeader.TLabel",
        )
        self.server_count_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        ttk.Label(
            frame,
            text="Provide connection details for your Proxmox host. You can add multiple servers.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self.server_fields_frame = ttk.Frame(frame, style="Wizard.Card.TFrame")
        self.server_fields_frame.pack(fill=tk.BOTH, expand=True)

        self._add_labeled_entry(
            self.server_fields_frame,
            "Proxmox Host/IP (e.g., https://192.168.1.10:8006)",
            self.proxmox_host_var,
        )
        self._add_labeled_entry(
            self.server_fields_frame,
            "Proxmox Username (e.g., root@pam)",
            self.proxmox_user_var,
        )
        self._add_labeled_entry(
            self.server_fields_frame,
            "Proxmox Password",
            self.proxmox_password_var,
            show="*",
        )

        buttons_frame = ttk.Frame(frame, style="Wizard.Card.TFrame")
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        self.add_server_button = ttk.Button(
            buttons_frame,
            text="Add Another Server",
            command=self._add_another_server,
            style="Wizard.Secondary.TButton",
        )
        self.add_server_button.pack(side=tk.LEFT)

        self._update_server_count_label()

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
                _styled_error(self, "Missing information", "Username and password are required.")
                return False

            if password != confirm_password:
                _styled_error(self, "Password mismatch", "Passwords do not match.")
                return False

            if self.store.account_exists(username):
                _styled_error(self, "Account exists", "This username is already in use.")
                return False

        elif self.current_step == 1:
            host = self.proxmox_host_var.get().strip()
            user = self.proxmox_user_var.get().strip()
            password = self.proxmox_password_var.get()

            if not host or not user or not password:
                _styled_error(self, "Missing information", "All Proxmox fields are required.")
                return False

        return True

    def _update_server_count_label(self) -> None:
        """Update the server count label in the header."""
        count = len(self.servers) + 1  # +1 for current server being entered
        if count == 1:
            self.server_count_label.config(text="")
        else:
            self.server_count_label.config(text=f"Server {count}")

    def _add_another_server(self) -> None:
        """Save current server and clear fields for next server."""
        host = self.proxmox_host_var.get().strip()
        user = self.proxmox_user_var.get().strip()
        password = self.proxmox_password_var.get()

        if not host or not user or not password:
            _styled_error(self, "Missing information", "Please fill in all fields before adding another server.")
            return

        # Validate and fetch certificate for this server
        try:
            normalized_host, pem_cert, fingerprint = fetch_server_certificate(host)
        except Exception as exc:
            _styled_error(
                self,
                "Certificate error",
                f"Unable to retrieve the server certificate:\n{exc}",
            )
            return

        if not prompt_trust_dialog(self, normalized_host, fingerprint):
            _styled_info(
                self,
                "Trust required",
                "You must trust the server certificate to continue.",
            )
            return

        # Store server config (cert will be saved later in _complete_wizard)
        username = self.username_var.get().strip()
        cert_path = self.store.save_trusted_cert(f"{username}_server_{len(self.servers)}", pem_cert)
        
        server_config = {
            "host": normalized_host,
            "username": user,
            "password": password,
            "verify_ssl": True,
            "trusted_cert": cert_path,
            "trusted_cert_fingerprint": fingerprint,
            "name": normalized_host,  # Default name, can be customized later
        }
        
        self.servers.append(server_config)
        
        # Clear fields for next server
        self.proxmox_host_var.set("")
        self.proxmox_user_var.set("")
        self.proxmox_password_var.set("")
        
        self._update_server_count_label()
        _styled_info(self, "Server added", f"Server {len(self.servers)} added. You can add another or click Finish.")

    def _complete_wizard(self) -> None:
        username = self.username_var.get().strip()
        password = self.password_var.get()
        salt = os.urandom(16).hex()
        host_input = self.proxmox_host_var.get().strip()

        # Validate current server fields
        if not host_input or not self.proxmox_user_var.get().strip() or not self.proxmox_password_var.get():
            _styled_error(self, "Missing information", "Please fill in all Proxmox fields or add the server first.")
            return

        # Process the current server being entered
        try:
            normalized_host, pem_cert, fingerprint = fetch_server_certificate(host_input)
        except Exception as exc:
            _styled_error(
                self,
                "Certificate error",
                f"Unable to retrieve the server certificate:\n{exc}",
            )
            return

        if not prompt_trust_dialog(self, normalized_host, fingerprint):
            _styled_info(
                self,
                "Trust required",
                "You must trust the server certificate to continue.",
            )
            return

        cert_path = self.store.save_trusted_cert(f"{username}_server_{len(self.servers)}", pem_cert)
        
        current_server = {
            "host": normalized_host,
            "username": self.proxmox_user_var.get().strip(),
            "password": self.proxmox_password_var.get(),
            "verify_ssl": True,
            "trusted_cert": cert_path,
            "trusted_cert_fingerprint": fingerprint,
            "name": normalized_host,  # Default name
        }
        
        # Combine all servers (previously added + current)
        all_servers = self.servers + [current_server]

        account_payload = {
            "username": username,
            "password": {
                "salt": salt,
                "hash": hash_password(password, salt),
            },
            "proxmox_servers": all_servers,
            "active_server_index": 0,  # First server is active by default
        }

        saved = self.store.save_account(account_payload)

        def finalize() -> None:
            self.destroy()
            if callable(self.on_complete):
                self.on_complete(saved)

        server_count = len(all_servers)
        server_text = f"{server_count} server{'s' if server_count > 1 else ''}"
        show_completion_dialog(
            self,
            f"Your local account and {server_text} have been stored securely.",
            finalize,
        )


__all__ = ["AccountStore", "SetupWizard"]

