import os
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import font, messagebox, ttk
from typing import Any

from add_container_view import build_view as build_add_container_view
from add_vm_view import build_view as build_add_vm_view
from app_settings_view import build_view as build_app_settings_view
from create_disk_view import build_view as build_create_disk_view
from list_disks_view import build_view as build_list_disks_view
from manage_containers_view import build_view as build_manage_containers_view
from manage_vms_view import build_view as build_manage_vms_view
from preferences import get_preference, get_preferences, set_preference
from proxmox_client import ProxmoxAPIError, ProxmoxClient, ProxmoxSummary
from server_settings_view import build_view as build_server_settings_view
from shell_view import build_view as build_shell_view
from vm_console_launcher import launch_vm_console
from theme import (
    PROXMOX_ACCENT,
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
)
from wizard import AccountStore, SetupWizard

WINDOW_WIDTH = 1024
WINDOW_HEIGHT = 768


def apply_window_mode_from_preferences(root: tk.Tk) -> None:
    apply_fn = getattr(root, "apply_window_mode", None)
    if callable(apply_fn):
        apply_fn("windowed")


def format_bytes(amount: int | float | None) -> str:
    if not amount:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(amount)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_percentage(used: int | float | None, total: int | float | None) -> str:
    if not used or not total or total == 0:
        return "0%"
    return f"{(used / total) * 100:.1f}%"


def format_duration(seconds: int | None) -> str:
    if not seconds:
        return "N/A"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{sec}s")
    return " ".join(parts)


def get_active_proxmox_config(account: dict | None) -> dict[str, Any] | None:
    """Get the active Proxmox server configuration from account.
    
    Supports both old format (single proxmox) and new format (multiple servers).
    Returns the active server config or the single proxmox config for backward compatibility.
    """
    if not account:
        return None
    
    # New format: multiple servers
    if "proxmox_servers" in account:
        servers = account.get("proxmox_servers", [])
        active_index = account.get("active_server_index", 0)
        if servers and 0 <= active_index < len(servers):
            return servers[active_index]
        elif servers:
            # Fallback to first server if index is invalid
            return servers[0]
        return None
    
    # Old format: single proxmox config (backward compatibility)
    if "proxmox" in account:
        return account["proxmox"]
    
    return None


def get_all_proxmox_servers(account: dict | None) -> list[dict[str, Any]]:
    """Get all Proxmox server configurations from account.
    
    Returns list of server configs, converting old format if needed.
    """
    if not account:
        return []
    
    # New format: multiple servers
    if "proxmox_servers" in account:
        return account.get("proxmox_servers", [])
    
    # Old format: single proxmox config (convert to list for compatibility)
    if "proxmox" in account:
        return [account["proxmox"]]
    
    return []


def set_active_server(account: dict, server_index: int) -> None:
    """Set the active server index in the account."""
    if "proxmox_servers" in account:
        servers = account.get("proxmox_servers", [])
        if 0 <= server_index < len(servers):
            account["active_server_index"] = server_index


def _styled_warning(parent: tk.Widget, title: str, message: str) -> None:
    """Show a styled warning dialog matching the app theme."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(True, True)
    dialog.minsize(600, 250)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 300
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 125
    dialog.geometry(f"600x250+{x}+{y}")
    
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
        wraplength=550,
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


def styled_warning(title: str, message: str, parent: tk.Widget | None = None) -> None:
    """Show a styled warning dialog. Uses root window if parent not provided."""
    if parent is None:
        # Try to get root window
        root = tk._default_root
        if root is None:
            # Fallback to messagebox
            import tkinter.messagebox as messagebox
            messagebox.showwarning(title, message)
            return
        parent = root
    _styled_warning(parent, title, message)


def styled_info(title: str, message: str, parent: tk.Widget | None = None) -> None:
    """Show a styled info dialog. Uses root window if parent not provided."""
    if parent is None:
        root = tk._default_root
        if root is None:
            import tkinter.messagebox as messagebox
            messagebox.showinfo(title, message)
            return
        parent = root
    
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(True, True)
    dialog.minsize(600, 250)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 300
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 125
    dialog.geometry(f"600x250+{x}+{y}")
    
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
        wraplength=550,
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


def styled_error(title: str, message: str, parent: tk.Widget | None = None) -> None:
    """Show a styled error dialog. Uses root window if parent not provided."""
    if parent is None:
        root = tk._default_root
        if root is None:
            import tkinter.messagebox as messagebox
            messagebox.showerror(title, message)
            return
        parent = root
    
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(True, True)
    dialog.minsize(600, 250)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 300
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 125
    dialog.geometry(f"600x250+{x}+{y}")
    
    tk.Label(
        dialog,
        text=title,
        font=("Segoe UI", 14, "bold"),
        fg="#f44336",
        bg=PROXMOX_DARK,
        anchor="w",
    ).pack(fill=tk.X, padx=24, pady=(20, 6))
    
    tk.Label(
        dialog,
        text=message,
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        wraplength=550,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=24, pady=(0, 16))
    
    actions = tk.Frame(dialog, bg=PROXMOX_DARK)
    actions.pack(fill=tk.X, padx=24, pady=(0, 20))
    
    tk.Button(
        actions,
        text="Close",
        command=dialog.destroy,
        font=("Segoe UI", 11, "bold"),
        bg="#f44336",
        fg="white",
        activebackground="#d32f2f",
        activeforeground="white",
        bd=0,
        padx=18,
        pady=8,
    ).pack(side=tk.RIGHT)
    
    dialog.wait_window()


def check_server_availability(server_config: dict[str, Any]) -> tuple[bool, str | None]:
    """Check if a server is reachable.
    
    Returns:
        (is_available, error_message)
    """
    host = server_config.get("host")
    username = server_config.get("username")
    password = server_config.get("password")
    verify_ssl = server_config.get("verify_ssl", False)
    trusted_cert = server_config.get("trusted_cert")
    trusted_fp = server_config.get("trusted_cert_fingerprint")
    
    if not all([host, username, password]):
        return False, "Incomplete credentials"
    
    client: ProxmoxClient | None = None
    try:
        client = ProxmoxClient(
            host=host,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            trusted_cert=trusted_cert,
            trusted_fingerprint=trusted_fp,
        )
        # Try a simple API call to verify connection
        client.get_nodes()
        return True, None
    except Exception as exc:
        error_msg = str(exc)
        # Check for common connection errors
        if "no route to host" in error_msg.lower() or "errno 113" in error_msg.lower():
            return False, "Server is down or unreachable"
        elif "connection" in error_msg.lower() and "refused" in error_msg.lower():
            return False, "Connection refused"
        elif "timeout" in error_msg.lower():
            return False, "Connection timeout"
        else:
            return False, f"Connection error: {error_msg}"
    finally:
        if client:
            client.close()


def find_first_available_server(account: dict) -> int | None:
    """Find the first available server in the account.
    
    Returns the index of the first available server, or None if none are available.
    """
    servers = get_all_proxmox_servers(account)
    if not servers:
        return None
    
    for idx, server in enumerate(servers):
        is_available, _ = check_server_availability(server)
        if is_available:
            return idx
    
    return None


def _switch_server(root: tk.Tk, account: dict, servers: list[dict[str, Any]], selected_name: str) -> None:
    """Switch to the selected server and refresh the dashboard."""
    # Find the server index by name
    for idx, server in enumerate(servers):
        server_name = server.get("name") or server.get("host", "Unknown")
        if server_name == selected_name:
            # Check if server is available before switching (in background to avoid blocking)
            def check_and_switch() -> None:
                is_available, error_msg = check_server_availability(server)
                
                def update_ui() -> None:
                    if not is_available:
                        # Show styled warning message
                        _styled_warning(
                            root,
                            "Server Unavailable",
                            f"Server '{server_name}' is currently down or unreachable.\n\n{error_msg or 'Unable to connect to server.'}",
                        )
                        # Don't switch to unavailable server
                        return
                    
                    set_active_server(account, idx)
                    # Save the account
                    store = getattr(root, "account_store", None)
                    if store:
                        store.save_account(account)
                    # Clear dashboard data and refresh
                    root.app_state["dashboard_data"] = None  # type: ignore[index]
                    fetch_dashboard_data(root, mode="full", force=True)
                
                root.after(0, update_ui)
            
            # Run check in background thread
            threading.Thread(target=check_and_switch, daemon=True).start()
            break


def clear_content(root: tk.Tk) -> None:
    for widget in root.content_frame.winfo_children():
        widget.destroy()


CARD_MIN_WIDTH = 420
DEFAULT_AUTO_REFRESH_INTERVAL_MS = 15000  # 15 seconds


def create_card(parent: tk.Widget, title: str) -> tuple[tk.Frame, tk.Frame]:
    card = tk.Frame(parent, bg=PROXMOX_MEDIUM, highlightthickness=0, bd=0)
    heading = tk.Label(
        card,
        text=title,
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    )
    heading.pack(anchor=tk.W, pady=(10, 5), padx=15)
    divider = tk.Frame(card, bg=PROXMOX_ORANGE, height=2)
    divider.pack(fill=tk.X, padx=15, pady=(0, 15))
    body = tk.Frame(card, bg=PROXMOX_MEDIUM)
    body.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    return card, body


def add_stat_row(parent: tk.Widget, label_text: str, value_text: str) -> None:
    row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
    row.pack(fill=tk.X, pady=4)
    label = tk.Label(
        row,
        text=label_text,
        font=("Segoe UI", 11, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
        width=22,
        anchor="w",
    )
    label.pack(side=tk.LEFT)
    value = tk.Label(
        row,
        text=value_text,
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        justify=tk.LEFT,
        wraplength=600,
    )
    value.pack(side=tk.LEFT, fill=tk.X, expand=True)


def layout_cards(container: tk.Widget, cards: list[tk.Frame]) -> None:
    if not cards:
        return

    width = max(container.winfo_width(), CARD_MIN_WIDTH)
    columns = max(1, width // (CARD_MIN_WIDTH + 20))

    for card in cards:
        card.grid_forget()

    for idx, card in enumerate(cards):
        row = idx // columns
        col = idx % columns
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        container.grid_columnconfigure(col, weight=1)


def confirm_dialog(title: str, message: str, root: tk.Tk) -> bool:
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(root)
    dialog.grab_set()

    tk.Label(
        dialog,
        text=title,
        font=("Segoe UI", 13, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    ).pack(anchor=tk.W, padx=30, pady=(20, 5))

    tk.Label(
        dialog,
        text=message,
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_DARK,
        wraplength=420,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=30, pady=(0, 15))

    response = {"value": False}

    def choose(value: bool) -> None:
        response["value"] = value
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))
    tk.Button(
        buttons,
        text="Cancel",
        command=lambda: choose(False),
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=16,
        pady=6,
    ).pack(side=tk.RIGHT, padx=(10, 0))
    tk.Button(
        buttons,
        text="Confirm",
        command=lambda: choose(True),
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=6,
    ).pack(side=tk.RIGHT)

    dialog.wait_window()
    return response["value"]


def render_dashboard(root: tk.Tk, account: dict | None) -> None:
    clear_content(root)
    root.title("Proxmox-LDC | Home")
    root.app_state["current_view"] = "home"  # type: ignore[index]

    container = tk.Frame(root.content_frame, bg=PROXMOX_DARK)
    container.pack(fill=tk.BOTH, expand=True)

    # Header with server selector
    header_frame = tk.Frame(container, bg=PROXMOX_DARK)
    header_frame.pack(fill=tk.X, padx=30, pady=(30, 10))
    
    title_frame = tk.Frame(header_frame, bg=PROXMOX_DARK)
    title_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    header_font = font.Font(family="Helvetica", size=36, weight="bold")
    header = tk.Label(
        title_frame,
        text="Proxmox-LDC",
        font=header_font,
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    header.pack(side=tk.LEFT)

    # Server selector dropdown
    servers = get_all_proxmox_servers(account)
    if len(servers) > 1:
        server_selector_frame = tk.Frame(header_frame, bg=PROXMOX_DARK)
        server_selector_frame.pack(side=tk.RIGHT, padx=(20, 0))
        
        tk.Label(
            server_selector_frame,
            text="Server:",
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(side=tk.LEFT, padx=(0, 8))
        
        server_var = tk.StringVar()
        active_index = account.get("active_server_index", 0) if account else 0
        if 0 <= active_index < len(servers):
            server_name = servers[active_index].get("name") or servers[active_index].get("host", "Unknown")
            server_var.set(server_name)
        
        server_menu = tk.OptionMenu(
            server_selector_frame,
            server_var,
            *[s.get("name") or s.get("host", "Unknown") for s in servers],
            command=lambda selected: _switch_server(root, account, servers, selected),
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
        server_menu.pack(side=tk.LEFT)

    data: dict[str, Any] | None = root.app_state.get("dashboard_data")  # type: ignore[index]
    loading = root.app_state.get("dashboard_loading", False)  # type: ignore[index]

    if not account:
        tk.Label(
            container,
            text="No account configured. Please run the setup wizard.",
            font=("Segoe UI", 12),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(pady=30)
        return

    summary: ProxmoxSummary | None = data.get("summary") if data else None
    error = data.get("error") if data else None

    status_text = None
    if loading:
        status_text = "Loading latest Proxmox data..."
    elif not summary and not error:
        status_text = "Preparing to fetch Proxmox data..."

    if status_text:
        tk.Label(
            container,
            text=status_text,
            font=("Segoe UI", 12),
            fg="#cfd3da",
            bg=PROXMOX_DARK,
        ).pack(pady=(0, 20))

    cards_frame = tk.Frame(container, bg=PROXMOX_DARK)
    cards_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 0))
    cards: list[tk.Frame] = []

    if error:
        error_card, error_body = create_card(cards_frame, "Unable to load data")
        cards.append(error_card)
        tk.Label(
            error_body,
            text=str(error),
            font=("Segoe UI", 11),
            fg="#ffb3a7",
            bg=PROXMOX_MEDIUM,
            wraplength=900,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 10))
        tk.Button(
            error_body,
            text="Retry",
            command=lambda: fetch_dashboard_data(root, mode="full", force=True),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            bd=0,
            padx=16,
            pady=8,
        ).pack(anchor=tk.W)
        layout_cards(cards_frame, cards)
        return

    if not summary:
        return

    widgets: dict[str, dict] = {}
    widgets["host"] = render_specs_section(cards_frame, summary, account, cards)
    widgets["network"] = render_network_section(cards_frame, summary, cards)
    widgets["storage"] = render_storage_section(cards_frame, summary, cards)
    widgets["vm"] = render_vm_section(cards_frame, summary, cards)
    widgets["container"] = render_container_section(cards_frame, summary, cards)
    layout_cards(cards_frame, cards)
    cards_frame.bind(
        "<Configure>",
        lambda event, cf=cards_frame, c=cards: layout_cards(cf, c),
    )
    root.app_state["dashboard_widgets"] = widgets  # type: ignore[index]
    # Ensure content fills viewport right after dashboard is rendered
    try:
        refresher = getattr(root, "update_content_layout", None)
        if callable(refresher):
            root.after_idle(refresher)
            root.after(130, refresher)
    except Exception:
        pass


def update_dashboard_views(root: tk.Tk, account: dict | None, summary: ProxmoxSummary) -> None:
    widgets = root.app_state.get("dashboard_widgets")  # type: ignore[index]
    if not widgets or account is None:
        render_dashboard(root, account)
        return

    widgets["host"]["update"](summary, account)
    widgets["network"]["update"](summary)
    widgets["storage"]["update"](summary)
    widgets["vm"]["update"](summary)
    widgets["container"]["update"](summary)
    # Update the dock with currently running VMs
    try:
        refresher = getattr(root, "refresh_dock_panel", None)
        if callable(refresher):
            refresher()
    except Exception:
        pass


def open_update_view(root: tk.Tk) -> None:
    account = root.app_state.get("account")  # type: ignore[index]
    summary: ProxmoxSummary | None = (
        root.app_state.get("dashboard_data", {}).get("summary")  # type: ignore[index]
    )
    if not account or not summary or not summary.node_name:
        messagebox.showwarning("Unavailable", "No Proxmox node information available yet.")
        return

    proxmox_cfg = get_active_proxmox_config(account) or {}
    host = proxmox_cfg.get("host")
    username = proxmox_cfg.get("username")
    password = proxmox_cfg.get("password")
    verify_ssl = proxmox_cfg.get("verify_ssl", False)
    trusted_cert = proxmox_cfg.get("trusted_cert")
    trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
    node_name = summary.node_name

    if not all([host, username, password]):
        messagebox.showwarning("Missing credentials", "Proxmox credentials are incomplete.")
        return

    clear_content(root)
    root.title("Proxmox-LDC | Updates")
    root.app_state["current_view"] = "Updates"  # type: ignore[index]

    container = tk.Frame(root.content_frame, bg=PROXMOX_DARK)
    container.pack(fill=tk.BOTH, expand=True)

    header = tk.Label(
        container,
        text=f"Check for updates on {node_name}",
        font=("Segoe UI", 16, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    header.pack(anchor=tk.W, padx=30, pady=(20, 5))

    info = tk.Label(
        container,
        text=(
            "Review pending updates here, then switch to the Shell tab and use the "
            "'Run apt update & upgrade' button to perform the installation directly on the host."
        ),
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_DARK,
        wraplength=720,
        justify=tk.LEFT,
    )
    info.pack(anchor=tk.W, padx=30, pady=(0, 5))

    repo_alert = tk.Label(
        container,
        text="",
        font=("Segoe UI", 10, "bold"),
        fg="#ffb74d",
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
        wraplength=640,
    )
    repo_alert.pack(anchor=tk.W, padx=30, pady=(0, 10))

    text_frame = tk.Frame(container, bg=PROXMOX_DARK)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 10))

    scrollbar = tk.Scrollbar(text_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    output = tk.Text(
        text_frame,
        bg=PROXMOX_MEDIUM,
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        wrap=tk.WORD,
        yscrollcommand=scrollbar.set,
        state=tk.DISABLED,
    )
    output.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=output.yview)

    buttons = tk.Frame(container, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))

    tk.Button(
        buttons,
        text="Close",
        command=lambda: go_home(root),
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    ).pack(side=tk.RIGHT, padx=(10, 0))

    check_button = tk.Button(
        buttons,
        text="Check for updates",
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    )
    check_button.pack(side=tk.RIGHT)

    def log(message: str) -> None:
        output.configure(state=tk.NORMAL)
        output.insert(tk.END, message + "\n")
        output.see(tk.END)
        output.configure(state=tk.DISABLED)
        action_state["logs"].append(message)

    def run_in_thread(action):
        def wrapper():
            try:
                client = ProxmoxClient(
                    host=host,
                    username=username,
                    password=password,
                    verify_ssl=verify_ssl,
                    trusted_cert=trusted_cert,
                    trusted_fingerprint=trusted_fp,
                )
                return action(client)
            finally:
                if 'client' in locals():
                    client.close()

        thread = threading.Thread(target=lambda: thread_task(wrapper), daemon=True)
        thread.start()

    def thread_task(callable_fn):
        try:
            result = callable_fn()
            root.after(0, lambda r=result: handle_result(r))
        except ProxmoxAPIError as exc:
            root.after(0, lambda e=str(exc): handle_error(e))
        except Exception as exc:  # pragma: no cover
            root.after(0, lambda e=str(exc): handle_error(f"Unexpected error: {e}"))

    # To differentiate between check/install results.
    action_state = {"mode": None, "updates": [], "logs": []}

    def handle_result(result):
        mode = action_state["mode"]
        if mode == "check":
            updates = result.get("updates") if isinstance(result, dict) else result or []
            repos_ok = result.get("repos_ok") if isinstance(result, dict) else True
            if not repos_ok:
                update_repo_alert(
                    "Enterprise repositories detected without subscription.",
                    instructions=True,
                )
            else:
                repo_alert.config(text="")

            action_state["updates"] = updates
            if not updates:
                log("System is up to date. No packages pending.")
            else:
                log("Pending updates:\n")
                for pkg in updates:
                    name = (
                        pkg.get("package")
                        or pkg.get("Title")
                        or pkg.get("title")
                        or "unknown"
                    )
                    version = (
                        pkg.get("Version")
                        or pkg.get("version")
                        or pkg.get("current-version")
                        or pkg.get("OldVersion")
                        or ""
                    )
                    origin = pkg.get("origin") or pkg.get("repo") or pkg.get("ChangeLogUrl") or ""
                    log(f"- {name} {version} ({origin})")
                log(
                    "\nTo install these updates, open the Shell tab and use the "
                    "'Run apt update & upgrade' button to run the commands directly on the host."
                )
                check_button.config(state=tk.NORMAL)

    def handle_error(message: str) -> None:
        log(f"Error: {message}")
        check_button.config(state=tk.NORMAL)

    def check_updates() -> None:
        action_state["mode"] = "check"
        log("Refreshing package cache and checking for updates...")
        check_button.config(state=tk.DISABLED)

        def action(client: ProxmoxClient):
            client.refresh_apt_cache(node_name)
            repos_ok = check_repos_for_subscription(client)
            updates = client.list_available_updates(node_name)
            return {"updates": updates, "repos_ok": repos_ok}

        run_in_thread(action)


    def update_repo_alert(message: str, instructions: bool = False) -> None:
        repo_alert.config(text=message)
        if instructions:
            manual_steps = (
                "\n\nManual steps:\n"
                "1. SSH into the Proxmox host (ssh root@<host>).\n"
                "2. Edit /etc/apt/sources.list.d/pve-enterprise.list and comment out the enterprise entry.\n"
                "3. Add: deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n"
                "4. (Optional) Edit ceph list file similarly: deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription\n"
                "5. Run apt update on the host, then return here."
            )
            full_message = f"{message}{manual_steps}"
            repo_alert.config(text=full_message)
        log(message)

    def check_repos_for_subscription(client: ProxmoxClient) -> bool:
        repos = client.list_repositories(node_name)
        for repo in repos:
            name = (repo.get("name") or repo.get("handle") or "").lower()
            status = repo.get("status")
            if "enterprise" in name and status == "enabled":
                return False
        return True
    check_button.config(command=check_updates)
    check_updates()

def render_specs_section(
    parent: tk.Widget, summary: ProxmoxSummary, account: dict, cards: list[tk.Frame]
) -> dict:
    card, body = create_card(parent, "Proxmox Host Overview")
    cards.append(card)

    root = parent.winfo_toplevel()
    button_row = tk.Frame(card, bg=PROXMOX_MEDIUM)
    button_row.pack(anchor=tk.E, padx=15, pady=(0, 5))

    tk.Button(
        button_row,
        text="Check for updates",
        command=lambda: open_update_view(root),
        font=("Segoe UI", 10, "bold"),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=4,
    ).pack(side=tk.RIGHT, padx=(10, 0))

    tk.Button(
        button_row,
        text="Refresh data",
        command=lambda: request_manual_refresh(root),
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=12,
        pady=4,
    ).pack(side=tk.RIGHT)

    grid = tk.Frame(body, bg=PROXMOX_MEDIUM)
    grid.pack(fill=tk.X)

    def populate(summary_obj: ProxmoxSummary, account_obj: dict) -> None:
        for child in grid.winfo_children():
            child.destroy()

        version = summary_obj.version.get("version", "Unknown")
        release = summary_obj.version.get("release")
        version_text = f"{version} ({release})" if release else version
        add_stat_row(grid, "Proxmox Version", version_text)

        node_name = summary_obj.node_name or "Unknown"
        add_stat_row(grid, "Node", node_name)
        proxmox_cfg = get_active_proxmox_config(account_obj)
        if proxmox_cfg:
            add_stat_row(grid, "Host", proxmox_cfg.get("host", "Unknown"))

        node_status = summary_obj.node_status or {}
        add_stat_row(grid, "Status", node_status.get("status", "Unknown"))
        add_stat_row(grid, "Kernel", node_status.get("kversion", "Unknown"))
        add_stat_row(grid, "PVE Build", node_status.get("pveversion", "Unknown"))

        cpuinfo = node_status.get("cpuinfo", {})
        cpu_model = cpuinfo.get("model", "Unknown CPU")
        sockets = cpuinfo.get("sockets")
        cores = cpuinfo.get("cores")
        cpu_details = cpu_model
        if sockets and cores:
            cpu_details += f" ({sockets} sockets / {cores} cores)"
        add_stat_row(grid, "Processor", cpu_details)

        loadavg = node_status.get("loadavg")
        if isinstance(loadavg, list) and loadavg:
            load_text = ", ".join(str(v) for v in loadavg[:3])
            add_stat_row(grid, "Load Average", load_text)

        uptime = summary_obj.node_status.get("uptime") if summary_obj.node_status else None
        add_stat_row(grid, "Uptime", format_duration(uptime))

        memory = node_status.get("memory", {})
        mem_total = memory.get("total")
        mem_used = memory.get("used")
        mem_text = (
            f"{format_bytes(mem_used)} used / {format_bytes(mem_total)} total "
            f"({format_percentage(mem_used, mem_total)})"
        )
        add_stat_row(grid, "RAM", mem_text)

    populate(summary, account)
    return {"card": card, "update": populate}


def render_network_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Network Interfaces")
    cards.append(section)
    data_holder = {
        "items": [iface for iface in summary.network if iface.get("iface")]
    }

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "network_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "network_sort", sort_var.get())
        update_interface_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("status_up"),
            ("status_down"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_interfaces() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            iface
            for iface in data_holder["items"]
            if term in iface.get("iface", "").lower()
            or term in (iface.get("address") or iface.get("ip-address") or "").lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda iface: iface.get("iface", "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda iface: iface.get("iface", "").lower())
        elif key == "status_up":
            filtered.sort(key=lambda iface: 0 if iface.get("status") == "active" else 1)
        elif key == "status_down":
            filtered.sort(key=lambda iface: 0 if iface.get("status") != "active" else 1)
        return filtered

    def update_interface_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_interfaces()
        if not items:
            tk.Label(
                list_container,
                text="No matching interfaces.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for iface in items:
            render_interface_row(list_container, iface)

    def render_interface_row(parent: tk.Frame, iface: dict[str, Any]) -> None:
        name = iface.get("iface", "Unknown")
        address = iface.get("address") or iface.get("ip-address") or "N/A"
        status = iface.get("status")
        active_flag = iface.get("active", False)
        is_up = bool(active_flag) or (isinstance(status, str) and status.lower() in {"active", "up", "connected"})
        status_text = "UP" if is_up else "DOWN"
        status_color = "#4caf50" if is_up else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=address,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=status_text,
            font=("Segoe UI", 10, "bold"),
            fg=status_color,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT)

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, iface_data=iface, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_interface_details(frame, iface_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"Type: {iface.get('type', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    def render_interface_details(container_frame: tk.Frame, iface: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        status = iface.get("status")
        active_flag = iface.get("active", False)
        is_up = bool(active_flag) or (isinstance(status, str) and status.lower() in {"active", "up", "connected"})

        details = [
            ("Interface", iface.get("iface", "Unknown")),
            ("Status", "UP" if is_up else "DOWN"),
            ("Type", iface.get("type", "unknown")),
            ("Method", iface.get("method", "unknown")),
            ("Address", iface.get("address") or iface.get("ip-address") or "N/A"),
            ("MAC", iface.get("mac") or iface.get("hwaddr") or "N/A"),
            ("Bridge Ports", iface.get("bridge_ports") or "N/A"),
            ("Autostart", str(iface.get("autostart", False))),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_interface_list()
    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = [iface for iface in summary_obj.network if iface.get("iface")]
        update_interface_list()

    return {"card": section, "update": refresh}


def render_storage_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Storage Devices")
    cards.append(section)
    data_holder = {"items": list(summary.storage)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "storage_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "storage_sort", sort_var.get())
        update_storage_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("capacity_asc"),
            ("capacity_desc"),
            ("usage_asc"),
            ("usage_desc"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_storage() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            entry
            for entry in data_holder["items"]
            if term in (entry.get("storage") or "").lower()
            or term in (entry.get("type") or "").lower()
            or term in (entry.get("node") or "").lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda entry: (entry.get("storage") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda entry: (entry.get("storage") or "").lower())
        elif key == "capacity_desc":
            filtered.sort(key=lambda entry: entry.get("total", 0), reverse=True)
        elif key == "capacity_asc":
            filtered.sort(key=lambda entry: entry.get("total", 0))
        elif key == "usage_desc":
            filtered.sort(key=lambda entry: entry.get("used", 0), reverse=True)
        elif key == "usage_asc":
            filtered.sort(key=lambda entry: entry.get("used", 0))
        return filtered

    def update_storage_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_storage()
        if not items:
            tk.Label(
                list_container,
                text="No matching storage devices.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for entry in items:
            render_storage_row(list_container, entry)

    def render_storage_row(parent: tk.Frame, entry: dict[str, Any]) -> None:
        name = entry.get("storage", "Unnamed")
        storage_type = entry.get("type", "Unknown")

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=f"Type: {storage_type}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, entry_data=entry, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_storage_details(frame, entry_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

    def render_storage_details(container_frame: tk.Frame, entry: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        details = [
            ("Type", entry.get("type", "Unknown")),
            ("Node", entry.get("node", "Unknown")),
            ("Enabled", str(entry.get("enabled", True))),
            ("Shared", str(entry.get("shared", False))),
            ("Content", ", ".join(entry.get("content", "").split(",")) if entry.get("content") else "N/A"),
            ("Used", format_bytes(entry.get("used"))),
            ("Total", format_bytes(entry.get("total"))),
            ("Free", format_bytes(entry.get("total", 0) - entry.get("used", 0))),
            ("Usage", format_percentage(entry.get("used"), entry.get("total"))),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_storage_list()
    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.storage)
        update_storage_list()

    return {"card": section, "update": refresh}


def render_vm_section(
    parent: tk.Widget,
    summary: ProxmoxSummary,
    cards: list[tk.Frame],
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Virtual Machines")
    cards.append(section)
    data_holder = {"items": list(summary.vms)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "vm_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "vm_sort", sort_var.get())
        update_vm_list()

    combobox_style = ttk.Style()
    combobox_style.theme_use("clam")
    combobox_style.configure(
        "Proxmox.TCombobox",
        fieldbackground="#1f242b",
        background="#1f242b",
        foreground=PROXMOX_LIGHT,
        bordercolor="#3a414d",
        arrowcolor=PROXMOX_LIGHT,
        padding=5,
        relief="flat",
        selectbackground="#2f3640",
        selectforeground=PROXMOX_LIGHT,
    )
    combobox_style.map(
        "Proxmox.TCombobox",
        fieldbackground=[("readonly", "#1f242b")],
        foreground=[("readonly", PROXMOX_LIGHT)],
    )

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("id_asc"),
            ("id_desc"),
            ("running_first"),
            ("stopped_first"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_vms() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            vm
            for vm in data_holder["items"]
            if term in (vm.get("name") or "").lower()
            or term in str(vm.get("vmid")).lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda vm: (vm.get("name") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda vm: (vm.get("name") or "").lower())
        elif key == "id_desc":
            filtered.sort(key=lambda vm: vm.get("vmid", 0), reverse=True)
        elif key == "id_asc":
            filtered.sort(key=lambda vm: vm.get("vmid", 0))
        elif key == "running_first":
            filtered.sort(key=lambda vm: 0 if vm.get("status") == "running" else 1)
        elif key == "stopped_first":
            filtered.sort(key=lambda vm: 0 if vm.get("status") != "running" else 1)
        return filtered

    def update_vm_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_vms()
        if not items:
            tk.Label(
                list_container,
                text="No matching VMs.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for vm in items:
            render_vm_row(list_container, vm)

    def render_vm_row(parent: tk.Frame, vm: dict[str, Any]) -> None:
        name = vm.get("name") or f"VM {vm.get('vmid')}"
        status = vm.get("status", "stopped")
        status_color = "#4caf50" if status == "running" else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, vm_data=vm, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_vm_details(frame, vm_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"VMID: {vm.get('vmid', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    update_vm_list()

    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.vms)
        update_vm_list()

    return {"card": section, "update": refresh}



def render_container_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "LXC Containers")
    cards.append(section)
    data_holder = {"items": list(summary.containers)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "container_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "container_sort", sort_var.get())
        update_ct_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("id_asc"),
            ("id_desc"),
            ("running_first"),
            ("stopped_first"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_cts() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            ct
            for ct in data_holder["items"]
            if term in (ct.get("name") or "").lower()
            or term in str(ct.get("vmid")).lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda ct: (ct.get("name") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda ct: (ct.get("name") or "").lower())
        elif key == "id_desc":
            filtered.sort(key=lambda ct: ct.get("vmid", 0), reverse=True)
        elif key == "id_asc":
            filtered.sort(key=lambda ct: ct.get("vmid", 0))
        elif key == "running_first":
            filtered.sort(key=lambda ct: 0 if ct.get("status") == "running" else 1)
        elif key == "stopped_first":
            filtered.sort(key=lambda ct: 0 if ct.get("status") != "running" else 1)
        return filtered

    def update_ct_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_cts()
        if not items:
            tk.Label(
                list_container,
                text="No matching containers.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for ct in items:
            render_ct_row(list_container, ct)

    def render_ct_row(parent: tk.Frame, ct: dict[str, Any]) -> None:
        name = ct.get("name") or f"CT {ct.get('vmid')}"
        status = ct.get("status", "stopped")
        status_color = "#4caf50" if status == "running" else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, ct_data=ct, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_container_details(frame, ct_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"CTID: {ct.get('vmid', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    def render_container_details(container_frame: tk.Frame, ct: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        details = [
            ("CTID", str(ct.get("vmid", "N/A"))),
            ("Status", ct.get("status", "unknown")),
            ("Uptime", format_duration(ct.get("uptime"))),
            ("CPU Usage", f"{ct.get('cpu', 0)*100:.1f}%"),
            ("Memory", f"{format_bytes(ct.get('maxmem'))} max"),
            ("Disk", f"{format_bytes(ct.get('maxdisk'))} max"),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_ct_list()

    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.containers)
        update_ct_list()

    return {"card": section, "update": refresh}


def render_vm_details(container: tk.Frame, vm: dict[str, Any]) -> None:
    for child in container.winfo_children():
        child.destroy()

    network_lines = []
    network_defs = vm.get("network") or []
    if isinstance(network_defs, list):
        for net in network_defs:
            iface_name = net.get("name", "net")
            bridge = net.get("bridge", "N/A")
            mac = net.get("mac", "N/A")
            model = net.get("model", "")
            network_lines.append(f"{iface_name} ({model}) -> {bridge}, MAC {mac}")

    details = [
        ("VMID", str(vm.get("vmid", "N/A"))),
        ("Status", vm.get("status", "unknown")),
        ("Uptime", format_duration(vm.get("uptime"))),
        ("CPU Usage", f"{vm.get('cpu', 0)*100:.1f}%"),
        ("Memory", f"{format_bytes(vm.get('maxmem'))} max"),
        ("Disk", f"{format_bytes(vm.get('maxdisk'))} max"),
        ("PID", str(vm.get("pid", "N/A"))),
        ("Networks", "\n".join(network_lines) if network_lines else "N/A"),
    ]

    for label, value in details:
        row = tk.Frame(container, bg="#1f242b")
        row.pack(fill=tk.X, pady=1)
        tk.Label(
            row,
            text=f"{label}:",
            font=("Segoe UI", 10, "bold"),
            fg=PROXMOX_LIGHT,
            bg="#1f242b",
            width=12,
            anchor="w",
        ).pack(side=tk.LEFT)
        tk.Label(
            row,
            text=value,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg="#1f242b",
            anchor="w",
            justify=tk.LEFT,
            wraplength=750,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)


def show_setup_wizard(root: tk.Tk, store: AccountStore) -> None:
    clear_content(root)
    root.title("Proxmox-LDC | Setup")
    root.app_state["current_view"] = "setup"  # type: ignore[index]

    def on_complete(account: dict) -> None:
        wizard.destroy()
        root.app_state["account"] = account  # type: ignore[index]
        root.app_state["dashboard_data"] = None  # type: ignore[index]
        apply_window_mode_from_preferences(root)
        go_home(root)

    wizard = SetupWizard(root.content_frame, store, on_complete)
    wizard.pack(fill=tk.BOTH, expand=True)
    root.focus_force()


def create_root_window() -> tk.Tk:
    root = tk.Tk()
    root.title("Proxmox-LDC")
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    root.configure(bg=PROXMOX_DARK)
    # Prevent collapsing to a tiny sliver when switching modes
    try:
        root.minsize(800, 600)
    except Exception:
        pass
    default_geometry = f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}"
    root._default_geometry = default_geometry  # type: ignore[attr-defined]
    root._windowed_geometry = default_geometry  # type: ignore[attr-defined]
    root._window_mode = "windowed"  # type: ignore[attr-defined]
    root.app_state = {  # type: ignore[attr-defined]
        "account": None,
        "dashboard_data": None,
        "dashboard_loading": False,
        "current_view": "home",
    }
    root.open_consoles = {}  # type: ignore[attr-defined]
    root.option_add("*Menu.background", PROXMOX_MEDIUM)
    root.option_add("*Menu.foreground", PROXMOX_LIGHT)
    root.option_add("*Menu.activeBackground", PROXMOX_ORANGE)
    root.option_add("*Menu.activeForeground", "white")
    root.option_add("*Menu.relief", "flat")
    root.option_add("*Menu.font", "Helvetica 11")
    root.option_add("*Menu.selectColor", PROXMOX_ACCENT)

    # Main area with left slide-out consoles panel and content canvas
    main_area = tk.Frame(root, bg=PROXMOX_DARK)
    main_area.pack(fill=tk.BOTH, expand=True)

    # Without a dock, the main content spans the entire area.
    root.refresh_dock_panel = lambda: None  # type: ignore[attr-defined]
    root.refresh_consoles_panel = lambda: None  # type: ignore[attr-defined]

    container = tk.Frame(main_area, bg=PROXMOX_DARK)
    container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(
        container,
        bg=PROXMOX_DARK,
        highlightthickness=0,
        borderwidth=0,
    )
    canvas.pack(fill=tk.BOTH, expand=True)
    content = tk.Frame(canvas, bg=PROXMOX_DARK)
    frame_window = canvas.create_window((0, 0), window=content, anchor="nw")

    def on_mousewheel(event: tk.Event) -> None:
        current_view = root.app_state.get("current_view")
        if str(current_view).lower() == "shell":
            return
        delta = event.delta
        if event.num == 4:  # Linux scroll up
            delta = 120
        elif event.num == 5:  # Linux scroll down
            delta = -120
        canvas.yview_scroll(int(-1 * (delta / 120)), "units")

    def on_key_scroll(event: tk.Event) -> None:  # pragma: no cover
        current_view = root.app_state.get("current_view")
        if str(current_view).lower() == "shell":
            return
        if event.keysym == "Up":
            canvas.yview_scroll(-1, "units")
        elif event.keysym == "Down":
            canvas.yview_scroll(1, "units")
        elif event.keysym == "Prior":  # Page Up
            canvas.yview_scroll(-8, "units")
        elif event.keysym == "Next":  # Page Down
            canvas.yview_scroll(8, "units")
        elif event.keysym == "Home":
            canvas.yview_moveto(0)
        elif event.keysym == "End":
            canvas.yview_moveto(1)

    root.bind_all("<MouseWheel>", on_mousewheel)
    root.bind_all("<Button-4>", on_mousewheel)
    root.bind_all("<Button-5>", on_mousewheel)
    root.bind_all("<Up>", on_key_scroll)
    root.bind_all("<Down>", on_key_scroll)
    root.bind_all("<Prior>", on_key_scroll)
    root.bind_all("<Next>", on_key_scroll)
    root.bind_all("<Home>", on_key_scroll)
    root.bind_all("<End>", on_key_scroll)

    def update_scroll_region(event: tk.Event | None) -> None:
        # Ensure the scrollregion reflects all content and the window item
        # stretches to at least the canvas size to avoid a blank bottom area.
        req_h = content.winfo_reqheight()
        cvs_h = canvas.winfo_height()
        content_height = max(req_h, cvs_h)
        content_width = canvas.winfo_width()
        canvas.configure(scrollregion=(0, 0, content_width, content_height))
        # Only force height to canvas height if content is shorter; otherwise let content drive height for scrolling
        if req_h < cvs_h:
            canvas.itemconfig(frame_window, width=content_width, height=content_height)
        else:
            canvas.itemconfig(frame_window, width=content_width, height=req_h)

    content.bind("<Configure>", update_scroll_region)
    def on_canvas_configure(event: tk.Event) -> None:
        # Keep the embedded window sized to the canvas; taller content will scroll.
        req_h = content.winfo_reqheight()
        cvs_h = event.height
        if req_h < cvs_h:
            canvas.itemconfig(frame_window, width=event.width, height=cvs_h)
        else:
            canvas.itemconfig(frame_window, width=event.width, height=req_h)
        update_scroll_region(event)
    canvas.bind("<Configure>", on_canvas_configure)
    # Expose a helper to refresh embedded content sizing from other views
    try:
        root.update_content_layout = lambda: update_scroll_region(None)  # type: ignore[attr-defined]
    except Exception:
        pass
    # Kick an initial layout update so the first draw fills the viewport
    try:
        root.after_idle(lambda: update_scroll_region(None))
        # Perform a second pass shortly after to catch late geometry changes
        root.after(120, lambda: update_scroll_region(None))
    except Exception:
        pass

    root.content_canvas = canvas  # type: ignore[attr-defined]
    root.content_frame = content  # type: ignore[attr-defined]

    def apply_window_mode(mode: str) -> None:
        normalized = "fullscreen" if str(mode).lower() == "fullscreen" else "windowed"
        current = getattr(root, "_window_mode", "windowed")
        if normalized == current and not root.attributes("-fullscreen") == (normalized == "fullscreen"):
            # Continue to reconcile state below
            pass
        # Avoid WM glitches by withdrawing, changing state, then deiconify/lift
        try:
            root.withdraw()
        except Exception:
            pass
        if normalized == "fullscreen":
            # Remember last windowed geometry so we can restore later
            try:
                root._windowed_geometry = root.geometry()  # type: ignore[attr-defined]
            except Exception:
                pass
            root.attributes("-fullscreen", True)
        else:
            root.attributes("-fullscreen", False)
            # Ensure the window has a sensible size and apply stored geometry
            try:
                root.update_idletasks()
            except Exception:
                pass
            geometry = getattr(root, "_windowed_geometry", None) or getattr(root, "_default_geometry", None)
            try:
                if geometry:
                    root.geometry(geometry)
            except Exception:
                pass
            try:
                root.state("normal")
            except Exception:
                pass
        root._window_mode = normalized  # type: ignore[attr-defined]
        def _show() -> None:
            try:
                root.deiconify()
                root.lift()
                root.focus_force()
            except Exception:
                pass
        root.after(50, _show)
        # Recalculate content layout after mode change and geometry restoration
        try:
            refresher = getattr(root, "update_content_layout", None)
            if callable(refresher):
                root.after(80, refresher)
                root.after(180, refresher)
        except Exception:
            pass

    root.apply_window_mode = apply_window_mode  # type: ignore[attr-defined]

    def record_windowed_geometry(event: tk.Event) -> None:
        if getattr(root, "_window_mode", "windowed") != "windowed":
            return
        if root.attributes("-fullscreen"):
            return
        root._windowed_geometry = root.geometry()  # type: ignore[attr-defined]
        # Refresh content layout on any window geometry change to avoid black band
        try:
            refresher = getattr(root, "update_content_layout", None)
            if callable(refresher):
                # Use after_idle to debounce rapid Configure events
                root.after_idle(refresher)
        except Exception:
            pass

    root.bind("<Configure>", record_windowed_geometry)

    root.trigger_dashboard_refresh = lambda mode="full", force=True: fetch_dashboard_data(root, mode=mode, force=force)  # type: ignore[attr-defined]

    # Console session helpers
    root._console_sessions = 0  # type: ignore[attr-defined]
    root._pre_console_window_mode = None  # type: ignore[attr-defined]

    def on_console_launch() -> None:
        try:
            root._console_sessions += 1  # type: ignore[attr-defined]
        except Exception:
            root._console_sessions = 1  # type: ignore[attr-defined]
        # If we're in fullscreen, temporarily switch to windowed so external windows aren't hidden
        if getattr(root, "_window_mode", "windowed") == "fullscreen":
            root._pre_console_window_mode = "fullscreen"  # type: ignore[attr-defined]
            apply_window_mode("windowed")
        # Do not lower/minimize here; wait until after viewer successfully launches

    def on_console_exit() -> None:
        try:
            root._console_sessions = max(0, int(getattr(root, "_console_sessions", 1)) - 1)  # type: ignore[attr-defined]
        except Exception:
            root._console_sessions = 0  # type: ignore[attr-defined]
        if root._console_sessions == 0:  # type: ignore[attr-defined]
            # Restore previous window mode if needed
            prev = getattr(root, "_pre_console_window_mode", None)
            if prev == "fullscreen":
                apply_window_mode("fullscreen")
                root._pre_console_window_mode = None  # type: ignore[attr-defined]
            try:
                root.deiconify()
                root.lift()
            except Exception:
                pass

    def after_console_launch() -> None:
        # Consoles open in their own windows; no additional app behavior required.
        return

    root.on_console_launch = on_console_launch  # type: ignore[attr-defined]
    root.on_console_exit = on_console_exit  # type: ignore[attr-defined]
    root.after_console_launch = after_console_launch  # type: ignore[attr-defined]

    return root


def open_placeholder_view(root: tk.Tk, builder, title: str) -> None:
    clear_content(root)
    root.title(f"Proxmox-LDC | {title}")
    root.app_state["current_view"] = title  # type: ignore[index]
    frame = builder(root.content_frame)
    frame.pack(fill=tk.BOTH, expand=True)
    # Ensure content fills viewport right after view is rendered
    try:
        refresher = getattr(root, "update_content_layout", None)
        if callable(refresher):
            root.after_idle(refresher)
            root.after(130, refresher)
    except Exception:
        pass


def open_documentation(root: tk.Tk) -> None:
    """Open the documentation HTML file in the default web browser."""
    # Get the directory where the script is located
    script_dir = Path(__file__).parent.absolute()
    doc_path = script_dir / "documentation.html"
    
    # If documentation doesn't exist, create a basic one
    if not doc_path.exists():
        create_default_documentation(doc_path)
    
    # Open in browser
    try:
        webbrowser.open(f"file://{doc_path}")
    except Exception as exc:
        messagebox.showerror(
            "Error",
            f"Failed to open documentation:\n{exc}",
            parent=root,
        )


def create_default_documentation(doc_path: Path) -> None:
    """Create a default documentation HTML file."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxmox-LDC Documentation</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #ff6600;
            border-bottom: 3px solid #ff6600;
            padding-bottom: 10px;
        }
        h2 {
            color: #ff6600;
            margin-top: 30px;
            border-bottom: 2px solid #ff6600;
            padding-bottom: 5px;
        }
        h3 {
            color: #666;
            margin-top: 20px;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #c7254e;
        }
        pre {
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #ff6600;
        }
        .section {
            background-color: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        ul, ol {
            margin-left: 20px;
        }
        li {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <h1>Proxmox-LDC Documentation</h1>
    
    <div class="section">
        <h2>Introduction</h2>
        <p>Proxmox-LDC is a desktop client for managing Proxmox servers. It provides an intuitive graphical interface for managing virtual machines, containers, and server resources.</p>
    </div>
    
    <div class="section">
        <h2>Getting Started</h2>
        <h3>Initial Setup</h3>
        <ol>
            <li>Launch the application</li>
            <li>Follow the setup wizard to configure your Proxmox server connection</li>
            <li>Enter your Proxmox server URL, username, and password</li>
            <li>Trust the server certificate when prompted</li>
        </ol>
        
        <h3>Adding Multiple Servers</h3>
        <p>You can add multiple Proxmox servers during setup or later in Server Settings. Use the server dropdown on the home dashboard to switch between servers.</p>
    </div>
    
    <div class="section">
        <h2>Features</h2>
        
        <h3>Dashboard</h3>
        <p>The home dashboard provides an overview of your Proxmox server, including:</p>
        <ul>
            <li>Server statistics (CPU, memory, disk usage)</li>
            <li>List of virtual machines with status indicators</li>
            <li>List of containers with status indicators</li>
            <li>Quick actions for VMs and containers</li>
        </ul>
        
        <h3>Virtual Machine Management</h3>
        <p>Access via <strong>Virtual Machines → Manage virtual machines</strong>:</p>
        <ul>
            <li>View all VMs with their current status</li>
            <li>Start, stop, and restart VMs</li>
            <li>Open VM console (SPICE/VNC) in separate windows</li>
            <li>View detailed VM information and statistics</li>
            <li>Search and sort VMs</li>
        </ul>
        
        <h3>Container Management</h3>
        <p>Access via <strong>Containers → Manage Containers</strong>:</p>
        <ul>
            <li>View all containers with their current status</li>
            <li>Start, stop, and restart containers</li>
            <li>Open container console via SSH</li>
            <li>View detailed container information and statistics</li>
            <li>Search and sort containers</li>
        </ul>
        
        <h3>Creating Virtual Machines</h3>
        <p>Access via <strong>Virtual Machines → Add a virtual machine</strong>:</p>
        <p>Use the wizard to create new VMs with options for:</p>
        <ul>
            <li>VM name and ID</li>
            <li>Node selection</li>
            <li>CPU and memory allocation</li>
            <li>Storage configuration</li>
            <li>Network settings</li>
            <li>ISO image selection</li>
        </ul>
        
        <h3>Server Settings</h3>
        <p>Access via <strong>Settings → Server Settings</strong>:</p>
        <ul>
            <li>View and edit server connection details</li>
            <li>Add new servers</li>
            <li>Remove servers</li>
            <li>Manage certificate trust</li>
            <li>Switch between multiple servers</li>
        </ul>
        
        <h3>App Settings</h3>
        <p>Access via <strong>Settings → App Settings</strong>:</p>
        <ul>
            <li>Configure custom configuration folder location</li>
            <li>Manage application preferences</li>
        </ul>
        
        <h3>Shell Access</h3>
        <p>Access via <strong>Settings → Shell</strong>:</p>
        <p>Provides SSH terminal access to your Proxmox host for advanced operations.</p>
    </div>
    
    <div class="section">
        <h2>Console Access</h2>
        
        <h3>VM Consoles</h3>
        <p>Virtual machines can be accessed via SPICE or VNC consoles, which open in separate windows using <code>remote-viewer</code> (virt-viewer).</p>
        <p><strong>Note:</strong> VMs configured with external displays cannot be accessed via console.</p>
        
        <h3>Container Consoles</h3>
        <p>Containers are accessed via SSH terminal. The app will:</p>
        <ol>
            <li>Open a terminal window</li>
            <li>Connect via SSH to your Proxmox host</li>
            <li>Automatically enter the container using <code>pct enter</code></li>
        </ol>
        <p>You will be prompted for your SSH password (same as your Proxmox API password).</p>
    </div>
    
    <div class="section">
        <h2>Tips and Troubleshooting</h2>
        
        <h3>Console Not Working</h3>
        <ul>
            <li><strong>VMs:</strong> Ensure the VM is running and has SPICE/VNC enabled</li>
            <li><strong>Containers:</strong> Ensure SSH is enabled on your Proxmox host and the container is running</li>
            <li>Install <code>virt-viewer</code> for VM console access: <code>sudo apt install virt-viewer</code></li>
        </ul>
        
        <h3>Certificate Errors</h3>
        <p>If you see certificate errors, go to <strong>Settings → Server Settings</strong> and click "Trust Server Certificate".</p>
        
        <h3>Data Not Updating</h3>
        <p>Use the "Refresh" button in the Manage VMs/Containers view, or refresh the dashboard to get the latest data from Proxmox.</p>
    </div>
    
    <div class="section">
        <h2>Keyboard Shortcuts</h2>
        <ul>
            <li>Use the menu bar to navigate between different views</li>
            <li>Search boxes allow filtering of VMs and containers</li>
            <li>Sort options are available in the Manage views</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Support</h2>
        <p>For issues, feature requests, or contributions, please refer to the project repository.</p>
    </div>
</body>
</html>
"""
    try:
        with open(doc_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception:
        pass  # If we can't create it, that's okay


def show_about_dialog(root: tk.Tk) -> None:
    """Show the About information in the main window."""
    clear_content(root)
    root.title("Proxmox-LDC | About")
    root.app_state["current_view"] = "About"  # type: ignore[index]
    
    frame = tk.Frame(root.content_frame, bg=PROXMOX_DARK)
    frame.pack(fill=tk.BOTH, expand=True)
    
    content = tk.Frame(frame, bg=PROXMOX_DARK)
    content.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
    
    # Title
    tk.Label(
        content,
        text="Proxmox-LDC",
        font=("Segoe UI", 32, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(pady=(20, 10))
    
    # Version
    tk.Label(
        content,
        text="Version 0.1 Beta",
        font=("Segoe UI", 14),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    ).pack(pady=(0, 30))
    
    # Description
    description = (
        "Proxmox-LDC is a desktop client for managing Proxmox servers.\n\n"
        "It provides an intuitive graphical interface for managing virtual\n"
        "machines, containers, and server resources from your desktop.\n\n"
        "Features:\n"
        "• Multi-server support\n"
        "• VM and container management\n"
        "• Console access (SPICE/VNC for VMs, SSH for containers)\n"
        "• Resource monitoring and statistics\n"
        "• Easy-to-use wizard for creating VMs"
    )
    
    tk.Label(
        content,
        text=description,
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
        wraplength=800,
    ).pack(pady=(0, 30))
    
    # Author/Credits
    tk.Label(
        content,
        text="Developed for Proxmox server management",
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_DARK,
    ).pack(pady=(20, 0))
    
    # Ensure content fills viewport
    try:
        refresher = getattr(root, "update_content_layout", None)
        if callable(refresher):
            root.after_idle(refresher)
            root.after(130, refresher)
    except Exception:
        pass


def request_manual_refresh(root: tk.Tk) -> None:
    fetch_dashboard_data(root, mode="full", force=True)


def ensure_auto_refresh(root: tk.Tk) -> None:
    """Start auto-refresh if enabled in preferences."""
    # Check if auto-refresh is enabled
    auto_refresh_enabled = get_preference(root, "auto_refresh_enabled", True)
    if not auto_refresh_enabled:
        return
    
    if getattr(root, "_auto_refresh_started", False):  # type: ignore[attr-defined]
        return
    root._auto_refresh_started = True  # type: ignore[attr-defined]

    # Get refresh interval from preferences (default 15 seconds)
    interval_seconds = get_preference(root, "auto_refresh_interval_seconds", 15)
    interval_ms = interval_seconds * 1000

    def tick() -> None:
        if not root.winfo_exists():
            return
        # Check again if auto-refresh is still enabled
        auto_refresh_enabled = get_preference(root, "auto_refresh_enabled", True)
        if not auto_refresh_enabled:
            root._auto_refresh_started = False  # type: ignore[attr-defined]
            return
        
        if root.app_state.get("current_view") == "home":  # type: ignore[index]
            fetch_dashboard_data(root, mode="auto")
        
        # Get current interval (in case it changed)
        interval_seconds = get_preference(root, "auto_refresh_interval_seconds", 15)
        interval_ms = interval_seconds * 1000
        root._auto_refresh_id = root.after(interval_ms, tick)  # type: ignore[attr-defined]

    root._auto_refresh_id = root.after(interval_ms, tick)  # type: ignore[attr-defined]


def go_home(root: tk.Tk) -> None:
    account = root.app_state.get("account")  # type: ignore[index]
    
    # If multiple servers exist, check if active server is available in background
    # If not, auto-switch to first available server
    def check_and_switch() -> None:
        if account:
            servers = get_all_proxmox_servers(account)
            if len(servers) > 1:
                active_config = get_active_proxmox_config(account)
                if active_config:
                    is_available, _ = check_server_availability(active_config)
                    if not is_available:
                        # Active server is down, try to find an available one
                        available_idx = find_first_available_server(account)
                        if available_idx is not None:
                            set_active_server(account, available_idx)
                            store = getattr(root, "account_store", None)
                            if store:
                                store.save_account(account)
                            # Refresh dashboard with new server
                            root.after(0, lambda: fetch_dashboard_data(root, mode="full", force=True))
    
    # Run check in background thread to avoid blocking UI
    threading.Thread(target=check_and_switch, daemon=True).start()
    
    render_dashboard(root, account)
    fetch_dashboard_data(root, mode="full", force=True)
    ensure_auto_refresh(root)


def fetch_dashboard_data(root: tk.Tk, *, mode: str = "auto", force: bool = False) -> None:
    if root.app_state.get("dashboard_loading") and not force:  # type: ignore[index]
        return

    account = root.app_state.get("account")  # type: ignore[index]
    if not account:
        return

    proxmox = get_active_proxmox_config(account) or {}
    host = proxmox.get("host")
    username = proxmox.get("username")
    password = proxmox.get("password")
    verify_ssl = proxmox.get("verify_ssl", False)
    trusted_cert = proxmox.get("trusted_cert")
    trusted_fp = proxmox.get("trusted_cert_fingerprint")

    if not all([host, username, password]):
        root.app_state["dashboard_data"] = {"error": "Incomplete Proxmox credentials."}  # type: ignore[index]
        if root.app_state.get("current_view") == "home":  # type: ignore[index]
            render_dashboard(root, account)
        return

    root.app_state["dashboard_loading"] = True  # type: ignore[index]

    existing_summary = (
        root.app_state.get("dashboard_data", {}).get("summary")  # type: ignore[index]
        if mode != "full"
        else None
    )

    def task() -> None:
        client: ProxmoxClient | None = None
        try:
            client = ProxmoxClient(
                host=host,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
                trusted_cert=trusted_cert,
                trusted_fingerprint=trusted_fp,
            )
            if mode == "full" or existing_summary is None:
                summary = client.fetch_summary()
            else:
                summary = update_runtime_summary(client, existing_summary)
            payload = {"summary": summary}
        except ProxmoxAPIError as exc:
            error_msg = str(exc)
            # Check if this is a connection error
            if "no route to host" in error_msg.lower() or "errno 113" in error_msg.lower() or "connection" in error_msg.lower():
                # Try to auto-switch to available server if multiple servers exist
                servers = get_all_proxmox_servers(account)
                if len(servers) > 1:
                    available_idx = find_first_available_server(account)
                    if available_idx is not None:
                        # Auto-switch to available server
                        set_active_server(account, available_idx)
                        store = getattr(root, "account_store", None)
                        if store:
                            store.save_account(account)
                        # Retry with new server
                        root.after(0, lambda: fetch_dashboard_data(root, mode=mode, force=True))
                        return
                    else:
                        payload = {"error": "All servers are currently down or unreachable."}
                else:
                    # Single server - show error
                    payload = {"error": "Server is down or unreachable. Please ensure the server is running and try again."}
            else:
                payload = {"error": str(exc)}
        except Exception as exc:  # pragma: no cover
            error_msg = str(exc)
            # Check if this is a connection error
            if "no route to host" in error_msg.lower() or "errno 113" in error_msg.lower() or "connection" in error_msg.lower():
                # Try to auto-switch to available server if multiple servers exist
                servers = get_all_proxmox_servers(account)
                if len(servers) > 1:
                    available_idx = find_first_available_server(account)
                    if available_idx is not None:
                        # Auto-switch to available server
                        set_active_server(account, available_idx)
                        store = getattr(root, "account_store", None)
                        if store:
                            store.save_account(account)
                        # Retry with new server
                        root.after(0, lambda: fetch_dashboard_data(root, mode=mode, force=True))
                        return
                    else:
                        payload = {"error": "All servers are currently down or unreachable."}
                else:
                    # Single server - show error
                    payload = {"error": "Server is down or unreachable. Please ensure the server is running and try again."}
            else:
                payload = {"error": f"Unexpected error: {exc}"}
        finally:
            if client:
                client.close()

        root.after(0, lambda: _on_dashboard_data(root, payload))

    threading.Thread(target=task, daemon=True).start()


def _on_dashboard_data(root: tk.Tk, payload: dict[str, Any]) -> None:
    root.app_state["dashboard_loading"] = False  # type: ignore[index]
    root.app_state["dashboard_data"] = payload  # type: ignore[index]
    if root.app_state.get("current_view") == "home":  # type: ignore[index]
        summary = payload.get("summary")
        account = root.app_state.get("account")  # type: ignore[index]
        if summary and root.app_state.get("dashboard_widgets"):
            update_dashboard_views(root, account, summary)
        else:
            render_dashboard(root, account)


def update_runtime_summary(
    client: ProxmoxClient, existing: ProxmoxSummary
) -> ProxmoxSummary:
    node_name = existing.node_name
    if not node_name:
        return client.fetch_summary()

    node_status = client.get_node_status(node_name)
    vms_runtime = client.get_node_vms(node_name)
    containers_runtime = client.get_node_containers(node_name)

    existing_networks = {
        vm.get("vmid"): vm.get("network") for vm in existing.vms if vm.get("vmid") is not None
    }

    for vm in vms_runtime:
        net = existing_networks.get(vm.get("vmid"))
        if net:
            vm["network"] = net

    return ProxmoxSummary(
        version=existing.version,
        node_name=node_name,
        node_status=node_status,
        network=existing.network,
        storage=existing.storage,
        vms=vms_runtime,
        containers=containers_runtime,
    )


def setup_menu(root: tk.Tk) -> None:
    menu_kwargs = {
        "tearoff": 0,
        "bg": PROXMOX_MEDIUM,
        "fg": PROXMOX_LIGHT,
        "activebackground": PROXMOX_ORANGE,
        "activeforeground": "white",
        "bd": 0,
        "relief": "flat",
    }

    menubar = tk.Menu(root, **menu_kwargs)

    file_menu = tk.Menu(menubar, **menu_kwargs)
    file_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)

    menubar.add_command(
        label="Home",
        command=lambda: go_home(root),
    )

    settings_menu = tk.Menu(menubar, **menu_kwargs)
    settings_menu.add_command(
        label="App Settings",
        command=lambda: open_placeholder_view(root, build_app_settings_view, "App Settings"),
    )
    settings_menu.add_command(
        label="Server Settings",
        command=lambda: open_placeholder_view(root, build_server_settings_view, "Server Settings"),
    )
    settings_menu.add_command(
        label="Shell",
        command=lambda: open_placeholder_view(root, build_shell_view, "Shell"),
    )
    menubar.add_cascade(label="Settings", menu=settings_menu)

    # Disks menu
    disks_menu = tk.Menu(menubar, **menu_kwargs)
    disks_menu.add_command(
        label="List disks & Directories",
        command=lambda: open_placeholder_view(root, build_list_disks_view, "List Disks & Directories"),
    )
    disks_menu.add_command(
        label="Create VM disk",
        command=lambda: open_placeholder_view(root, build_create_disk_view, "Create VM Disk"),
    )
    menubar.add_cascade(label="Disks", menu=disks_menu)

    # Consoles menu removed per new design (use left dock instead)

    vm_menu = tk.Menu(menubar, **menu_kwargs)
    vm_menu.add_command(
        label="Add a virtual machine",
        command=lambda: open_placeholder_view(root, build_add_vm_view, "Add a Virtual Machine"),
    )
    vm_menu.add_command(
        label="Manage virtual machines",
        command=lambda: open_placeholder_view(root, build_manage_vms_view, "Manage Virtual Machines"),
    )
    menubar.add_cascade(label="Virtual Machines", menu=vm_menu)

    container_menu = tk.Menu(menubar, **menu_kwargs)
    container_menu.add_command(
        label="Add a Container",
        command=lambda: open_placeholder_view(root, build_add_container_view, "Add a Container"),
    )
    container_menu.add_command(
        label="Manage Containers",
        command=lambda: open_placeholder_view(
            root, build_manage_containers_view, "Manage Containers"
        ),
    )
    menubar.add_cascade(label="Containers", menu=container_menu)

    # Help menu
    help_menu = tk.Menu(menubar, **menu_kwargs)
    help_menu.add_command(
        label="Documentation",
        command=lambda: open_documentation(root),
    )
    help_menu.add_command(
        label="About",
        command=lambda: show_about_dialog(root),
    )
    menubar.add_cascade(label="Help", menu=help_menu)

    root.config(menu=menubar)

    # Helpers to manage/refresh consoles menu
    import shutil as _sh
    import subprocess as _sp

    def _focus_console(vmid: int) -> None:
        info = getattr(root, "open_consoles", {}).get(vmid)  # type: ignore[attr-defined]
        if not info:
            return
        title = str(info.get("title", f"VM {vmid}"))
        win_id = info.get("win_id")
        try:
            if win_id and _sh.which("wmctrl"):
                _sp.call(["wmctrl", "-i", "-a", str(win_id)])
                return
        except Exception:
            pass
        if _sh.which("wmctrl"):
            try:
                _sp.call(["wmctrl", "-a", title])
                return
            except Exception:
                pass
        if _sh.which("xdotool"):
            try:
                _sp.call(["xdotool", "search", "--name", title, "windowactivate"])
                return
            except Exception:
                pass

    def _close_console(vmid: int) -> None:
        info = getattr(root, "open_consoles", {}).get(vmid)  # type: ignore[attr-defined]
        if not info:
            return
        proc = info.get("proc")
        try:
            if proc:
                proc.terminate()
        except Exception:
            pass
        try:
            del root.open_consoles[vmid]  # type: ignore[attr-defined]
        except Exception:
            pass
        refresh_consoles_menu()

    def refresh_consoles_menu() -> None:
        m = getattr(root, "consoles_menu", None)  # type: ignore[attr-defined]
        if not m:
            return
        m.delete(0, "end")
        items = list(getattr(root, "open_consoles", {}).items())  # type: ignore[attr-defined]
        if not items:
            m.add_command(label="No open consoles", state="disabled")
        else:
            for vmid, info in items:
                label = str(info.get("title", f"VM {vmid}"))
                m.add_command(label=f"Focus: {label}", command=lambda vid=vmid: _focus_console(vid))
                m.add_command(label=f"Close:  {label}", command=lambda vid=vmid: _close_console(vid))

    root.refresh_consoles_menu = refresh_consoles_menu  # type: ignore[attr-defined]


def main() -> None:
    root = create_root_window()
    
    # Try to load custom config directory from default location
    default_config = Path.home() / ".config" / "Proxmox-LDC"
    custom_config_dir = None
    pref_file = default_config / "preferences.json"
    if pref_file.exists():
        try:
            import json
            with pref_file.open("r", encoding="utf-8") as f:
                prefs = json.load(f)
                custom_dir = prefs.get("config_dir")
                if custom_dir:
                    custom_config_dir = Path(custom_dir)
        except Exception:
            pass
    
    store = AccountStore(custom_config_dir)
    root.account_store = store  # type: ignore[attr-defined]
    setup_menu(root)

    def start_app() -> None:
        account = store.get_default_account()
        if account is None:
            show_setup_wizard(root, store)
        else:
            root.app_state["account"] = account  # type: ignore[index]
            apply_window_mode_from_preferences(root)
            go_home(root)

    root.after(0, start_app)
    root.mainloop()


if __name__ == "__main__":
    main()

