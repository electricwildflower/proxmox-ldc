import tkinter as tk

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_ORANGE
from vm_creation_wizard import VMCreationWizard


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


def build_view(parent: tk.Widget) -> tk.Frame:
    root = parent.winfo_toplevel()
    frame = tk.Frame(parent, bg=PROXMOX_DARK)

    title = tk.Label(
        frame,
        text="Add a Virtual Machine",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 10), padx=40)

    description = tk.Label(
        frame,
        text="Create a new virtual machine using the wizard below.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
    )
    description.pack(anchor=tk.W, padx=40, pady=(0, 20))

    # Get account and Proxmox config
    account = getattr(root, "app_state", {}).get("account")
    proxmox_config = _get_active_proxmox_config(account)

    if not proxmox_config:
        error_label = tk.Label(
            frame,
            text="Unable to load Proxmox configuration. Please check your server settings.",
            font=("Segoe UI", 11),
            fg="#ff6b6b",
            bg=PROXMOX_DARK,
            justify=tk.LEFT,
        )
        error_label.pack(anchor=tk.W, padx=40)
        return frame

    # Create wizard container
    wizard_container = tk.Frame(frame, bg=PROXMOX_DARK)
    wizard_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 40))

    def on_wizard_complete(result: dict) -> None:
        """Handle wizard completion - refresh dashboard if needed."""
        refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
        if callable(refresh_cb):
            refresh_cb(mode="full", force=True)

    wizard = VMCreationWizard(
        wizard_container,
        proxmox_config,
        on_complete=on_wizard_complete,
    )
    wizard.pack(fill=tk.BOTH, expand=True)

    return frame

