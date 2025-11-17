import tkinter as tk
from tkinter import messagebox

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE
from trust import (
    fetch_server_certificate,
    normalize_server_url,
    prompt_trust_dialog,
    show_certificate_details_dialog,
)


def _get_active_proxmox_config(account: dict | None) -> dict | None:
    """Get the active Proxmox server configuration from account."""
    if not account:
        return None
    
    # New format: multiple servers
    if "proxmox_servers" in account:
        servers = account.get("proxmox_servers", [])
        active_index = account.get("active_server_index", 0)
        if servers and 0 <= active_index < len(servers):
            return servers[active_index]
        elif servers:
            return servers[0]
        return None
    
    # Old format: single proxmox config (backward compatibility)
    if "proxmox" in account:
        return account["proxmox"]
    
    return None


def _get_active_server_index(account: dict) -> int:
    """Get the index of the active server."""
    if "proxmox_servers" in account:
        return account.get("active_server_index", 0)
    return 0  # Old format, treat as index 0


def _get_all_proxmox_servers(account: dict | None) -> list[dict]:
    """Get all Proxmox server configurations from account."""
    if not account:
        return []
    
    # New format: multiple servers
    if "proxmox_servers" in account:
        return account.get("proxmox_servers", [])
    
    # Old format: single proxmox config (convert to list for compatibility)
    if "proxmox" in account:
        return [account["proxmox"]]
    
    return []


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
    subtitle.pack(anchor=tk.W, padx=40, pady=(0, 10))
    
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

    # Server selector (if multiple servers exist)
    servers = _get_all_proxmox_servers(account)
    selected_server_index = [0]  # Use list to allow modification in nested functions
    
    # Get the selected server config
    def get_selected_server_config() -> dict:
        if len(servers) > 0 and 0 <= selected_server_index[0] < len(servers):
            return servers[selected_server_index[0]]
        return _get_active_proxmox_config(account) or {}
    
    # Initialize with active server
    active_index = account.get("active_server_index", 0) if account else 0
    if 0 <= active_index < len(servers):
        selected_server_index[0] = active_index
    
    # Initialize form variables first
    proxmox = get_selected_server_config()
    host_var = tk.StringVar(value=proxmox.get("host", ""))
    user_var = tk.StringVar(value=proxmox.get("username", ""))
    password_var = tk.StringVar(value=proxmox.get("password", ""))
    verify_var = tk.BooleanVar(value=bool(proxmox.get("verify_ssl", False)))
    status_var = tk.StringVar(value="")
    fingerprint_var = tk.StringVar(value=proxmox.get("trusted_cert_fingerprint", ""))
    
    # Server selector frame (always show if we have servers, or show add button)
    server_selector_frame = tk.Frame(frame, bg=PROXMOX_DARK)
    server_selector_frame.pack(fill=tk.X, padx=40, pady=(0, 20))
    
    server_var = tk.StringVar()
    server_menu = None
    
    def update_server_selector() -> None:
        """Update the server selector dropdown with current server list."""
        nonlocal server_menu, servers
        # Clear existing widgets
        for widget in server_selector_frame.winfo_children():
            widget.destroy()
        
        servers = _get_all_proxmox_servers(account)
        
        if len(servers) > 0:
            tk.Label(
                server_selector_frame,
                text="Select Server:",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            # Ensure selected index is valid
            if selected_server_index[0] >= len(servers):
                selected_server_index[0] = 0
            
            if 0 <= selected_server_index[0] < len(servers):
                server_name = servers[selected_server_index[0]].get("name") or servers[selected_server_index[0]].get("host", "Unknown")
                server_var.set(server_name)
            
            # Define selection handler
            def on_server_selected(selected_name: str) -> None:
                for idx, server in enumerate(servers):
                    server_name = server.get("name") or server.get("host", "Unknown")
                    if server_name == selected_name:
                        selected_server_index[0] = idx
                        # Update form fields
                        proxmox_cfg = get_selected_server_config()
                        host_var.set(proxmox_cfg.get("host", ""))
                        user_var.set(proxmox_cfg.get("username", ""))
                        password_var.set(proxmox_cfg.get("password", ""))
                        verify_var.set(bool(proxmox_cfg.get("verify_ssl", False)))
                        fingerprint_var.set(proxmox_cfg.get("trusted_cert_fingerprint", ""))
                        status_var.set("")
                        break
            
            server_menu = tk.OptionMenu(
                server_selector_frame,
                server_var,
                *[s.get("name") or s.get("host", "Unknown") for s in servers],
                command=on_server_selected,
            )
            server_menu.config(
                font=("Segoe UI", 11),
                bg=PROXMOX_MEDIUM,
                fg=PROXMOX_LIGHT,
                activebackground=PROXMOX_ORANGE,
                activeforeground="white",
                highlightthickness=0,
                bd=0,
                relief="flat",
            )
            server_menu["menu"].config(
                font=("Segoe UI", 11),
                bg=PROXMOX_MEDIUM,
                fg=PROXMOX_LIGHT,
                activebackground=PROXMOX_ORANGE,
                activeforeground="white",
            )
            server_menu.pack(side=tk.LEFT, padx=(0, 10))
        
        # Always show "Add Server" button
        tk.Button(
            server_selector_frame,
            text="+ Add Server",
            command=lambda: add_new_server(),
            font=("Segoe UI", 10, "bold"),
            bg="#4caf50",
            fg="white",
            activebackground="#45a049",
            activeforeground="white",
            bd=0,
            padx=12,
            pady=6,
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        # Add "Remove Server" button (only if more than one server)
        if len(servers) > 1:
            tk.Button(
                server_selector_frame,
                text="Remove Server",
                command=lambda: remove_current_server(),
                font=("Segoe UI", 10),
                bg="#f44336",
                fg="white",
                activebackground="#da190b",
                activeforeground="white",
                bd=0,
                padx=12,
                pady=6,
            ).pack(side=tk.LEFT)
    
    # Initialize server selector
    update_server_selector()

    store = getattr(root, "account_store", None)
    
    def add_new_server() -> None:
        """Open a dialog to add a new server."""
        if store is None:
            messagebox.showerror("Unavailable", "Account store is not available.", parent=root)
            return
        
        dialog = tk.Toplevel(root)
        dialog.title("Add New Server")
        dialog.configure(bg=PROXMOX_DARK)
        dialog.transient(root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        root.update_idletasks()
        x = root.winfo_rootx() + (root.winfo_width() // 2) - 300
        y = root.winfo_rooty() + (root.winfo_height() // 2) - 200
        dialog.geometry(f"600x400+{x}+{y}")
        
        tk.Label(
            dialog,
            text="Add New Server",
            font=("Segoe UI", 16, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        ).pack(anchor=tk.W, padx=24, pady=(20, 10))
        
        tk.Label(
            dialog,
            text="Enter the connection details for the new Proxmox server.",
            font=("Segoe UI", 11),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            wraplength=550,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=24, pady=(0, 20))
        
        form_frame = tk.Frame(dialog, bg=PROXMOX_DARK)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 20))
        
        new_host_var = tk.StringVar()
        new_user_var = tk.StringVar()
        new_password_var = tk.StringVar()
        
        def add_form_row(label_text: str, variable: tk.StringVar, show: str | None = None) -> None:
            row = tk.Frame(form_frame, bg=PROXMOX_DARK)
            row.pack(fill=tk.X, pady=8)
            tk.Label(
                row,
                text=label_text,
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
                width=20,
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
        
        add_form_row("Server URL", new_host_var)
        add_form_row("Username", new_user_var)
        add_form_row("Password", new_password_var, show="*")
        
        status_dialog_var = tk.StringVar(value="")
        status_label = tk.Label(
            dialog,
            textvariable=status_dialog_var,
            font=("Segoe UI", 10),
            fg="#7ddc88",
            bg=PROXMOX_DARK,
        )
        status_label.pack(anchor=tk.W, padx=24, pady=(0, 10))
        
        def save_new_server() -> None:
            host = new_host_var.get().strip()
            username = new_user_var.get().strip()
            password = new_password_var.get()
            
            if not host or not username or not password:
                status_dialog_var.set("Please fill in all fields.")
                return
            
            try:
                normalized_host, pem_cert, fingerprint = fetch_server_certificate(host)
            except Exception as exc:
                status_dialog_var.set(f"Certificate error: {exc}")
                return
            
            if not prompt_trust_dialog(dialog, normalized_host, fingerprint):
                status_dialog_var.set("You must trust the server certificate to continue.")
                return
            
            # Save certificate
            account_username = account.get("username", "default")
            new_server_idx = len(servers)
            cert_path = store.save_trusted_cert(f"{account_username}_server_{new_server_idx}", pem_cert)
            
            # Create new server config
            new_server = {
                "host": normalized_host,
                "username": username,
                "password": password,
                "verify_ssl": True,
                "trusted_cert": cert_path,
                "trusted_cert_fingerprint": fingerprint,
                "name": normalized_host,  # Default name
            }
            
            # Add to account
            if "proxmox_servers" not in account:
                # Convert old format to new format
                if "proxmox" in account:
                    account["proxmox_servers"] = [account["proxmox"]]
                    account["active_server_index"] = 0
                else:
                    account["proxmox_servers"] = []
            
            account["proxmox_servers"].append(new_server)
            store.save_account(account)
            
            # Update app state
            if isinstance(app_state, dict):
                app_state["account"] = account
                app_state["dashboard_data"] = None
            
            # Update UI
            selected_server_index[0] = len(account["proxmox_servers"]) - 1
            update_server_selector()
            
            # Update form fields to show new server
            proxmox_cfg = get_selected_server_config()
            host_var.set(proxmox_cfg.get("host", ""))
            user_var.set(proxmox_cfg.get("username", ""))
            password_var.set(proxmox_cfg.get("password", ""))
            verify_var.set(bool(proxmox_cfg.get("verify_ssl", False)))
            fingerprint_var.set(proxmox_cfg.get("trusted_cert_fingerprint", ""))
            
            status_var.set("New server added successfully.")
            dialog.destroy()
        
        buttons_frame = tk.Frame(dialog, bg=PROXMOX_DARK)
        buttons_frame.pack(fill=tk.X, padx=24, pady=(0, 20))
        
        tk.Button(
            buttons_frame,
            text="Cancel",
            command=dialog.destroy,
            font=("Segoe UI", 11),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=16,
            pady=8,
        ).pack(side=tk.RIGHT, padx=(10, 0))
        
        tk.Button(
            buttons_frame,
            text="Add Server",
            command=save_new_server,
            font=("Segoe UI", 11, "bold"),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            activeforeground="white",
            bd=0,
            padx=16,
            pady=8,
        ).pack(side=tk.RIGHT)
    
    def remove_current_server() -> None:
        """Remove the currently selected server."""
        if store is None:
            messagebox.showerror("Unavailable", "Account store is not available.", parent=root)
            return
        
        if len(servers) <= 1:
            messagebox.showwarning(
                "Cannot remove",
                "You must have at least one server configured. Cannot remove the last server.",
                parent=root,
            )
            return
        
        current_server = get_selected_server_config()
        server_name = current_server.get("name") or current_server.get("host", "Unknown")
        
        # Confirm removal
        if not messagebox.askyesno(
            "Confirm Removal",
            f"Are you sure you want to remove server '{server_name}'?\n\nThis action cannot be undone.",
            parent=root,
        ):
            return
        
        # Remove server from account
        if "proxmox_servers" in account:
            servers_list = account.get("proxmox_servers", [])
            idx_to_remove = selected_server_index[0]
            
            if 0 <= idx_to_remove < len(servers_list):
                servers_list.pop(idx_to_remove)
                
                # Adjust active server index if needed
                active_idx = account.get("active_server_index", 0)
                if idx_to_remove < active_idx:
                    # Removed server was before active, adjust index
                    account["active_server_index"] = active_idx - 1
                elif idx_to_remove == active_idx:
                    # Removed the active server, switch to first server
                    if len(servers_list) > 0:
                        account["active_server_index"] = 0
                    else:
                        account.pop("active_server_index", None)
                elif active_idx >= len(servers_list):
                    # Active index is now out of bounds, set to last server
                    account["active_server_index"] = len(servers_list) - 1
                
                # Update selected index
                if selected_server_index[0] >= len(servers_list):
                    selected_server_index[0] = len(servers_list) - 1
                
                store.save_account(account)
                
                # Update app state
                if isinstance(app_state, dict):
                    app_state["account"] = account
                    app_state["dashboard_data"] = None
                
                # Update UI
                update_server_selector()
                
                # Update form fields to show the now-selected server
                proxmox_cfg = get_selected_server_config()
                host_var.set(proxmox_cfg.get("host", ""))
                user_var.set(proxmox_cfg.get("username", ""))
                password_var.set(proxmox_cfg.get("password", ""))
                verify_var.set(bool(proxmox_cfg.get("verify_ssl", False)))
                fingerprint_var.set(proxmox_cfg.get("trusted_cert_fingerprint", ""))
                
                status_var.set(f"Server '{server_name}' removed.")
            else:
                messagebox.showerror("Error", "Invalid server index.", parent=root)
        else:
            messagebox.showwarning(
                "Cannot remove",
                "Cannot remove server from old format account. Please use the setup wizard.",
                parent=root,
            )

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

    def trust_server() -> None:
        if store is None:
            messagebox.showerror("Unavailable", "Account store is not available.", parent=root)
            return
        host_input = host_var.get().strip()
        if not host_input:
            messagebox.showerror("Missing host", "Enter a server URL before trusting.", parent=root)
            return
        try:
            normalized_host, pem_cert, fingerprint = fetch_server_certificate(host_input)
        except Exception as exc:
            messagebox.showerror(
                "Certificate error",
                f"Unable to retrieve the server certificate:\n{exc}",
                parent=root,
            )
            return
        if not prompt_trust_dialog(frame, normalized_host, fingerprint):
            status_var.set("Trust cancelled.")
            return
        username = account.get("username", "default")
        server_idx = selected_server_index[0]
        cert_path = store.save_trusted_cert(f"{username}_server_{server_idx}", pem_cert)
        
        # Get current server config
        current_proxmox = get_selected_server_config()
        current_proxmox["host"] = normalized_host
        current_proxmox["trusted_cert"] = cert_path
        current_proxmox["trusted_cert_fingerprint"] = fingerprint
        current_proxmox["verify_ssl"] = True
        
        # Update the selected server in account
        if "proxmox_servers" in account:
            servers_list = account.get("proxmox_servers", [])
            if 0 <= server_idx < len(servers_list):
                servers_list[server_idx] = current_proxmox
        else:
            # Old format
            account["proxmox"] = current_proxmox
        
        # Update form fields
        host_var.set(normalized_host)
        verify_var.set(True)
        fingerprint_var.set(fingerprint)
        
        store.save_account(account)
        status_var.set("Server certificate trusted.")

    trust_row = tk.Frame(form, bg=PROXMOX_MEDIUM)
    trust_row.pack(fill=tk.X, pady=(12, 0))
    tk.Button(
        trust_row,
        text="Fetch & Trust Certificate",
        command=trust_server,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.LEFT)

    def view_trusted_cert() -> None:
        current_proxmox = get_selected_server_config()
        pem_path = current_proxmox.get("trusted_cert")
        if not pem_path:
            messagebox.showinfo("No certificate", "No trusted certificate is configured.", parent=root)
            return
        try:
            show_certificate_details_dialog(frame, pem_path)
        except Exception as exc:
            messagebox.showerror("Unable to show certificate", str(exc), parent=root)

    def clear_trust() -> None:
        current_proxmox = get_selected_server_config()
        current_proxmox.pop("trusted_cert", None)
        current_proxmox.pop("trusted_cert_fingerprint", None)
        fingerprint_var.set("")
        verify_var.set(False)
        
        # Update the selected server in account
        if "proxmox_servers" in account:
            servers_list = account.get("proxmox_servers", [])
            server_idx = selected_server_index[0]
            if 0 <= server_idx < len(servers_list):
                servers_list[server_idx] = current_proxmox
        else:
            account["proxmox"] = current_proxmox
        
        if store:
            store.save_account(account)
        status_var.set("Trusted certificate removed.")

    actions_trust = tk.Frame(form, bg=PROXMOX_MEDIUM)
    actions_trust.pack(fill=tk.X, pady=(8, 0))
    tk.Button(
        actions_trust,
        text="View Certificate Details",
        command=view_trusted_cert,
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=14,
        pady=6,
    ).pack(side=tk.LEFT)
    tk.Button(
        actions_trust,
        text="Remove Trust",
        command=clear_trust,
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=14,
        pady=6,
    ).pack(side=tk.LEFT, padx=(10, 0))

    tk.Label(
        trust_row,
        textvariable=fingerprint_var,
        font=("Segoe UI", 10),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        wraplength=400,
        justify=tk.LEFT,
        padx=20,
    ).pack(side=tk.LEFT, padx=(15, 0))

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

        try:
            normalized_host = normalize_server_url(host)
        except ValueError as exc:
            messagebox.showerror("Invalid URL", str(exc), parent=root)
            return
        host_var.set(normalized_host)

        # Get current server config
        current_proxmox = get_selected_server_config()
        host_changed = normalized_host != current_proxmox.get("host")
        if host_changed:
            current_proxmox.pop("trusted_cert", None)
            current_proxmox.pop("trusted_cert_fingerprint", None)
            fingerprint_var.set("")

        if verify_var.get() and not current_proxmox.get("trusted_cert"):
            messagebox.showerror(
                "Trust required",
                "Please trust the server certificate before enabling verification.",
                parent=root,
            )
            return

        current_proxmox.update(
            {
                "host": normalized_host,
                "username": username,
                "password": password,
                "verify_ssl": bool(verify_var.get()),
            }
        )
        
        # Update the selected server in account
        if "proxmox_servers" in account:
            servers_list = account.get("proxmox_servers", [])
            server_idx = selected_server_index[0]
            if 0 <= server_idx < len(servers_list):
                servers_list[server_idx] = current_proxmox
        else:
            # Old format
            account["proxmox"] = current_proxmox
            
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

