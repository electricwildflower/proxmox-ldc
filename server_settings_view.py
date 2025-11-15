import tkinter as tk
from tkinter import messagebox

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE


def build_view(parent: tk.Widget) -> tk.Frame:
    root = parent.winfo_toplevel()
    frame = tk.Frame(parent, bg=PROXMOX_DARK)

    title = tk.Label(
        frame,
        text="Server Settings",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 4), padx=40)

    subtitle = tk.Label(
        frame,
        text="Update the Proxmox API endpoint and credentials used by this app.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
        wraplength=760,
    )
    subtitle.pack(anchor=tk.W, padx=40, pady=(0, 20))

    app_state = getattr(root, "app_state", None)
    account = app_state.get("account") if isinstance(app_state, dict) else None
    if not account:
        tk.Label(
            frame,
            text="No account is active. Please complete the setup wizard first.",
            font=("Segoe UI", 12),
            fg="#ffb3a7",
            bg=PROXMOX_DARK,
            justify=tk.LEFT,
            wraplength=700,
        ).pack(anchor=tk.W, padx=40, pady=(10, 0))
        return frame

    proxmox = account.setdefault("proxmox", {})
    host_var = tk.StringVar(value=proxmox.get("host", ""))
    user_var = tk.StringVar(value=proxmox.get("username", ""))
    password_var = tk.StringVar(value=proxmox.get("password", ""))
    verify_var = tk.BooleanVar(value=bool(proxmox.get("verify_ssl", False)))
    status_var = tk.StringVar(value="")

    form = tk.Frame(frame, bg=PROXMOX_MEDIUM)
    form.pack(fill=tk.X, padx=40, pady=(0, 20))

    def add_entry_row(label_text: str, variable: tk.StringVar, show: str | None = None) -> None:
        row = tk.Frame(form, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=8)
        tk.Label(
            row,
            text=label_text,
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
            width=24,
            anchor="w",
        ).pack(side=tk.LEFT, padx=(0, 10))
        entry = tk.Entry(
            row,
            textvariable=variable,
            show=show or "",
            font=("Segoe UI", 11),
            bg="#1f242b",
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground="#363c45",
            highlightcolor=PROXMOX_ORANGE,
        )
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    add_entry_row("Server URL", host_var)
    add_entry_row("Username", user_var)
    add_entry_row("Password", password_var, show="*")

    checkbox_row = tk.Frame(form, bg=PROXMOX_MEDIUM)
    checkbox_row.pack(fill=tk.X, pady=(12, 0))
    tk.Checkbutton(
        checkbox_row,
        text="Verify SSL certificates",
        variable=verify_var,
        font=("Segoe UI", 11),
        bg=PROXMOX_MEDIUM,
        fg=PROXMOX_LIGHT,
        activebackground=PROXMOX_MEDIUM,
        activeforeground=PROXMOX_LIGHT,
        selectcolor=PROXMOX_DARK,
        anchor="w",
        padx=0,
    ).pack(anchor=tk.W)

    def save_settings() -> None:
        host = host_var.get().strip()
        username = user_var.get().strip()
        password = password_var.get()

        if not host or not username or not password:
            messagebox.showerror(
                "Missing information",
                "Please enter a server URL, username, and password.",
                parent=root,
            )
            return

        proxmox.update(
            {
                "host": host,
                "username": username,
                "password": password,
                "verify_ssl": bool(verify_var.get()),
            }
        )
        account["proxmox"] = proxmox
        if isinstance(app_state, dict):
            app_state["account"] = account
            app_state["dashboard_data"] = None

        store = getattr(root, "account_store", None)
        if store:
            store.save_account(account)

        status_var.set("Server settings saved.")

    actions = tk.Frame(frame, bg=PROXMOX_DARK)
    actions.pack(fill=tk.X, padx=40)
    tk.Button(
        actions,
        text="Save changes",
        command=save_settings,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=10,
    ).pack(side=tk.LEFT)

    status = tk.Label(
        actions,
        textvariable=status_var,
        font=("Segoe UI", 10),
        fg="#7ddc88",
        bg=PROXMOX_DARK,
    )
    status.pack(side=tk.LEFT, padx=(15, 0))

    return frame

