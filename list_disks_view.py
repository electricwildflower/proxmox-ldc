from __future__ import annotations

import threading
import tkinter as tk
from typing import Any

from proxmox_client import ProxmoxAPIError, ProxmoxClient
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE


def format_bytes(amount: int | float | None) -> str:
    """Format bytes to human-readable format."""
    if not amount:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(amount)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


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
        text="List Disks & Directories",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 10), padx=40)

    description = tk.Label(
        frame,
        text="View all available disks, directories, and VM virtual disks.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
    )
    description.pack(anchor=tk.W, padx=40, pady=(0, 20))

    # Container for the two cards side by side
    cards_container = tk.Frame(frame, bg=PROXMOX_DARK)
    cards_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 40))
    cards_container.grid_columnconfigure(0, weight=3)  # Card1 gets 60% (3/5)
    cards_container.grid_columnconfigure(1, weight=2)  # Card2 gets 40% (2/5)
    cards_container.grid_rowconfigure(0, weight=1)  # Allow row to expand

    # Card 1: Disks & Directories
    card1 = tk.Frame(cards_container, bg=PROXMOX_MEDIUM, highlightthickness=0, bd=0)
    card1.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

    card1_header = tk.Label(
        card1,
        text="Storage Pools",
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    )
    card1_header.pack(anchor=tk.W, pady=(20, 10), padx=20)

    card1_divider = tk.Frame(card1, bg=PROXMOX_ORANGE, height=2)
    card1_divider.pack(fill=tk.X, padx=20, pady=(0, 15))

    # Card1 controls (sort and filter)
    card1_controls = tk.Frame(card1, bg=PROXMOX_MEDIUM)
    card1_controls.pack(fill=tk.X, padx=20, pady=(0, 10))

    tk.Label(
        card1_controls,
        text="Sort by Capacity:",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card1_sort_var = tk.StringVar(value="None")
    card1_sort_menu = tk.OptionMenu(
        card1_controls,
        card1_sort_var,
        "None",
        "Ascending",
        "Descending",
    )
    card1_sort_menu.config(
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        activebackground=PROXMOX_ORANGE,
        activeforeground="white",
        highlightthickness=0,
        bd=0,
    )
    card1_sort_menu.pack(side=tk.LEFT, padx=(0, 20))
    card1_sort_var.trace_add("write", lambda *args: apply_filters_and_sort())

    tk.Label(
        card1_controls,
        text="Filter by Type:",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card1_filter_type_var = tk.StringVar(value="All")
    card1_filter_type_menu = tk.OptionMenu(
        card1_controls,
        card1_filter_type_var,
        "All",
    )
    card1_filter_type_menu.config(
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        activebackground=PROXMOX_ORANGE,
        activeforeground="white",
        highlightthickness=0,
        bd=0,
    )
    card1_filter_type_menu.pack(side=tk.LEFT)

    card1_content = tk.Frame(card1, bg=PROXMOX_MEDIUM)
    card1_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

    # Scrollable area for card1
    card1_canvas = tk.Canvas(card1_content, bg=PROXMOX_MEDIUM, highlightthickness=0)
    card1_scrollable = tk.Frame(card1_canvas, bg=PROXMOX_MEDIUM)
    
    def update_card1_scroll(event: tk.Event = None) -> None:
        card1_canvas.update_idletasks()
        card1_canvas.configure(scrollregion=card1_canvas.bbox("all"))
    
    card1_scrollable.bind("<Configure>", update_card1_scroll)
    card1_canvas_window = card1_canvas.create_window((0, 0), window=card1_scrollable, anchor="nw")
    
    def configure_card1_canvas(event: tk.Event) -> None:
        canvas_width = event.width
        card1_canvas.itemconfig(card1_canvas_window, width=canvas_width)
        update_card1_scroll()
    
    card1_canvas.bind("<Configure>", configure_card1_canvas)
    card1_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    card1_canvas.focus_set()

    card1_status = tk.Label(
        card1_content,
        text="Loading storage pools...",
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
    )
    card1_status.pack(pady=20)
    
    def show_card1_loading() -> None:
        """Show loading message for card1."""
        card1_status.config(text="Loading storage pools...")
        card1_status.pack(pady=20)
    
    def hide_card1_status() -> None:
        """Hide status message for card1."""
        card1_status.pack_forget()

    # Card 2: VM Disks
    card2 = tk.Frame(cards_container, bg=PROXMOX_MEDIUM, highlightthickness=0, bd=0)
    card2.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

    card2_header = tk.Label(
        card2,
        text="VM Virtual Disks",
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    )
    card2_header.pack(anchor=tk.W, pady=(20, 10), padx=20)

    card2_divider = tk.Frame(card2, bg=PROXMOX_ORANGE, height=2)
    card2_divider.pack(fill=tk.X, padx=20, pady=(0, 15))

    # Card2 controls (sort and filter)
    card2_controls = tk.Frame(card2, bg=PROXMOX_MEDIUM)
    card2_controls.pack(fill=tk.X, padx=20, pady=(0, 10))

    tk.Label(
        card2_controls,
        text="Sort by Size:",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card2_sort_var = tk.StringVar(value="None")
    card2_sort_menu = tk.OptionMenu(
        card2_controls,
        card2_sort_var,
        "None",
        "Ascending",
        "Descending",
    )
    card2_sort_menu.config(
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        activebackground=PROXMOX_ORANGE,
        activeforeground="white",
        highlightthickness=0,
        bd=0,
    )
    card2_sort_menu.pack(side=tk.LEFT, padx=(0, 20))
    card2_sort_var.trace_add("write", lambda *args: apply_filters_and_sort())

    tk.Label(
        card2_controls,
        text="Filter Storage:",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card2_filter_storage_var = tk.StringVar(value="All")
    card2_filter_storage_menu = tk.OptionMenu(
        card2_controls,
        card2_filter_storage_var,
        "All",
    )
    card2_filter_storage_menu.config(
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        activebackground=PROXMOX_ORANGE,
        activeforeground="white",
        highlightthickness=0,
        bd=0,
    )
    card2_filter_storage_menu.pack(side=tk.LEFT, padx=(0, 20))

    tk.Label(
        card2_controls,
        text="Min Size (GB):",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card2_filter_min_size = tk.Entry(
        card2_controls,
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        width=8,
        bd=0,
        highlightthickness=1,
        highlightbackground=PROXMOX_ORANGE,
        highlightcolor=PROXMOX_ORANGE,
    )
    card2_filter_min_size.pack(side=tk.LEFT, padx=(0, 5))

    tk.Label(
        card2_controls,
        text="Max Size (GB):",
        font=("Segoe UI", 10),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT, padx=(0, 5))

    card2_filter_max_size = tk.Entry(
        card2_controls,
        font=("Segoe UI", 10),
        bg=PROXMOX_DARK,
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        width=8,
        bd=0,
        highlightthickness=1,
        highlightbackground=PROXMOX_ORANGE,
        highlightcolor=PROXMOX_ORANGE,
    )
    card2_filter_max_size.pack(side=tk.LEFT)
    card2_filter_min_size.bind("<KeyRelease>", lambda e: apply_filters_and_sort())
    card2_filter_max_size.bind("<KeyRelease>", lambda e: apply_filters_and_sort())

    card2_content = tk.Frame(card2, bg=PROXMOX_MEDIUM)
    card2_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

    # Scrollable area for card2
    card2_canvas = tk.Canvas(card2_content, bg=PROXMOX_MEDIUM, highlightthickness=0)
    card2_scrollable = tk.Frame(card2_canvas, bg=PROXMOX_MEDIUM)
    
    def update_card2_scroll(event: tk.Event = None) -> None:
        card2_canvas.update_idletasks()
        card2_canvas.configure(scrollregion=card2_canvas.bbox("all"))
    
    card2_scrollable.bind("<Configure>", update_card2_scroll)
    card2_canvas_window = card2_canvas.create_window((0, 0), window=card2_scrollable, anchor="nw")
    
    def configure_card2_canvas(event: tk.Event) -> None:
        canvas_width = event.width
        card2_canvas.itemconfig(card2_canvas_window, width=canvas_width)
        update_card2_scroll()
    
    card2_canvas.bind("<Configure>", configure_card2_canvas)
    card2_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    card2_canvas.focus_set()

    card2_status = tk.Label(
        card2_content,
        text="Loading VM disks...",
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
    )
    card2_status.pack(pady=20)
    
    def show_card2_loading() -> None:
        """Show loading message for card2."""
        card2_status.config(text="Loading VM disks...")
        card2_status.pack(pady=20)
    
    def hide_card2_status() -> None:
        """Hide status message for card2."""
        card2_status.pack_forget()

    # Mouse wheel scrolling for both cards
    def on_mousewheel(event: tk.Event) -> None:
        if event.delta:
            card1_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            card2_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"
    
    def on_mousewheel_linux_up(event: tk.Event) -> None:
        card1_canvas.yview_scroll(-3, "units")
        card2_canvas.yview_scroll(-3, "units")
        return "break"
    
    def on_mousewheel_linux_down(event: tk.Event) -> None:
        card1_canvas.yview_scroll(3, "units")
        card2_canvas.yview_scroll(3, "units")
        return "break"
    
    def bind_mousewheel_to_widget(widget: tk.Widget) -> None:
        widget.bind("<MouseWheel>", on_mousewheel)
        widget.bind("<Button-4>", on_mousewheel_linux_up)
        widget.bind("<Button-5>", on_mousewheel_linux_down)
        for child in widget.winfo_children():
            bind_mousewheel_to_widget(child)
    
    bind_mousewheel_to_widget(card1_canvas)
    bind_mousewheel_to_widget(card2_canvas)
    bind_mousewheel_to_widget(card1_scrollable)
    bind_mousewheel_to_widget(card2_scrollable)

    # Refresh button
    refresh_frame = tk.Frame(frame, bg=PROXMOX_DARK)
    refresh_frame.pack(fill=tk.X, padx=40, pady=(0, 20))

    # Store raw data for sorting/filtering
    raw_storage_entries: list[dict[str, Any]] = []
    raw_vm_disks: list[dict[str, Any]] = []

    def apply_filters_and_sort() -> None:
        """Apply current filters and sorting to data and update UI."""
        # Filter and sort storage entries
        filtered_storage = list(raw_storage_entries)
        
        # Filter by type
        filter_type = card1_filter_type_var.get()
        if filter_type != "All":
            filtered_storage = [s for s in filtered_storage if s.get("type") == filter_type]
        
        # Sort by capacity
        sort_order = card1_sort_var.get()
        if sort_order == "Ascending":
            filtered_storage.sort(key=lambda x: x.get("total") or 0)
        elif sort_order == "Descending":
            filtered_storage.sort(key=lambda x: x.get("total") or 0, reverse=True)
        
        # Filter and sort VM disks
        filtered_vm_disks = list(raw_vm_disks)
        
        # Filter by storage
        filter_storage = card2_filter_storage_var.get()
        if filter_storage != "All":
            filtered_vm_disks = [d for d in filtered_vm_disks if d.get("storage") == filter_storage]
        
        # Filter by size range
        try:
            min_size_gb = card2_filter_min_size.get().strip()
            if min_size_gb:
                min_size_bytes = float(min_size_gb) * 1024 * 1024 * 1024
                filtered_vm_disks = [d for d in filtered_vm_disks if (d.get("size") or 0) >= min_size_bytes]
        except (ValueError, AttributeError):
            pass
        
        try:
            max_size_gb = card2_filter_max_size.get().strip()
            if max_size_gb:
                max_size_bytes = float(max_size_gb) * 1024 * 1024 * 1024
                filtered_vm_disks = [d for d in filtered_vm_disks if (d.get("size") or 0) <= max_size_bytes]
        except (ValueError, AttributeError):
            pass
        
        # Sort VM disks by size
        sort_order_vm = card2_sort_var.get()
        if sort_order_vm == "Ascending":
            filtered_vm_disks.sort(key=lambda x: x.get("size") or 0)
        elif sort_order_vm == "Descending":
            filtered_vm_disks.sort(key=lambda x: x.get("size") or 0, reverse=True)
        
        # Update UI with filtered/sorted data
        render_storage_list(filtered_storage)
        render_vm_disks_list(filtered_vm_disks)

    def render_storage_list(storage_entries: list[dict[str, Any]]) -> None:
        """Render the storage list in card1."""
        # Hide loading status
        hide_card1_status()
        
        # Clear card1
        for widget in card1_scrollable.winfo_children():
            widget.destroy()
        
        if not storage_entries:
            tk.Label(
                card1_scrollable,
                text="No storage pools found.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(pady=20)
        else:
            # Header row
            header_row = tk.Frame(card1_scrollable, bg=PROXMOX_MEDIUM)
            header_row.pack(fill=tk.X, pady=(0, 10))
            
            tk.Label(
                header_row,
                text="Name",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=20,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Label(
                header_row,
                text="Type",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=15,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Label(
                header_row,
                text="Path / Mount",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=30,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))

            tk.Label(
                header_row,
                text="Capacity",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=20,
                anchor="w",
            ).pack(side=tk.LEFT)

            # Data rows
            for item in storage_entries:
                row = tk.Frame(card1_scrollable, bg=PROXMOX_MEDIUM)
                row.pack(fill=tk.X, pady=4)
                
                tk.Label(
                    row,
                    text=item.get("name", "Unknown"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=20,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))
                
                tk.Label(
                    row,
                    text=item.get("type", "Unknown"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=15,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))
                
                tk.Label(
                    row,
                    text=item.get("path", "N/A"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=30,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))

                total = item.get("total")
                avail = item.get("avail")
                capacity_text = (
                    f"{format_bytes(total)} (Free: {format_bytes(avail)})"
                    if total
                    else "N/A"
                )
                tk.Label(
                    row,
                    text=capacity_text,
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=20,
                    anchor="w",
                ).pack(side=tk.LEFT)
        
        update_card1_scroll()

    def render_vm_disks_list(vm_disks: list[dict[str, Any]]) -> None:
        """Render the VM disks list in card2."""
        # Hide loading status
        hide_card2_status()
        
        # Clear card2
        for widget in card2_scrollable.winfo_children():
            widget.destroy()
        
        if not vm_disks:
            tk.Label(
                card2_scrollable,
                text="No VM disks found.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(pady=20)
        else:
            # Header row
            header_row2 = tk.Frame(card2_scrollable, bg=PROXMOX_MEDIUM)
            header_row2.pack(fill=tk.X, pady=(0, 10))
            
            tk.Label(
                header_row2,
                text="Disk Name",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=20,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Label(
                header_row2,
                text="Size",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Label(
                header_row2,
                text="Storage",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=15,
                anchor="w",
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Label(
                header_row2,
                text="VM",
                font=("Segoe UI", 11, "bold"),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_MEDIUM,
                width=20,
                anchor="w",
            ).pack(side=tk.LEFT)
            
            # Data rows
            for disk in vm_disks:
                row = tk.Frame(card2_scrollable, bg=PROXMOX_MEDIUM)
                row.pack(fill=tk.X, pady=4)
                
                tk.Label(
                    row,
                    text=disk.get("name", "Unknown"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=20,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))
                
                size_text = format_bytes(disk.get("size", 0)) if disk.get("size") else "N/A"
                tk.Label(
                    row,
                    text=size_text,
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=12,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))
                
                tk.Label(
                    row,
                    text=disk.get("storage", "N/A"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=15,
                    anchor="w",
                ).pack(side=tk.LEFT, padx=(0, 10))
                
                tk.Label(
                    row,
                    text=disk.get("vm_name", "Unknown"),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=20,
                    anchor="w",
                ).pack(side=tk.LEFT)
        
        update_card2_scroll()

    def load_data() -> None:
        """Load disk and VM disk data from Proxmox."""
        # Show loading messages
        show_card1_loading()
        show_card2_loading()
        
        account = getattr(root, "app_state", {}).get("account")
        if not account:
            card1_status.config(text="No account configured.")
            card2_status.config(text="No account configured.")
            card1_status.pack(pady=20)
            card2_status.pack(pady=20)
            return

        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")

        if not all([host, username, password]):
            card1_status.config(text="Incomplete Proxmox credentials.")
            card2_status.config(text="Incomplete Proxmox credentials.")
            card1_status.pack(pady=20)
            card2_status.pack(pady=20)
            return

        def worker() -> None:
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

                # Get nodes
                nodes = client.get_nodes()
                if not nodes:
                    def show_error() -> None:
                        card1_status.config(text="No nodes found.")
                        card2_status.config(text="No nodes found.")
                        card1_status.pack(pady=20)
                        card2_status.pack(pady=20)
                    root.after(0, show_error)
                    return

                node_name = nodes[0].get("node")
                if not node_name:
                    def show_error() -> None:
                        card1_status.config(text="Unable to determine node name.")
                        card2_status.config(text="Unable to determine node name.")
                        card1_status.pack(pady=20)
                        card2_status.pack(pady=20)
                    root.after(0, show_error)
                    return

                # Get all storages
                storages = client.get_node_storage(node_name)
                
                # Collect storage pools only (directories, LVM, network shares, etc.)
                storage_entries: list[dict[str, Any]] = []
                valid_types = {
                    "dir",
                    "lvm",
                    "lvmthin",
                    "zfspool",
                    "rbd",
                    "nfs",
                    "cifs",
                    "cephfs",
                    "glusterfs",
                    "drbd",
                }
                for storage in storages:
                    storage_name = storage.get("storage", "")
                    storage_type = storage.get("type", "")
                    storage_path = storage.get("path", "") or storage.get("server", "") or "N/A"
                    total = storage.get("total")
                    avail = storage.get("avail")

                    if not storage_name:
                        continue

                    storage_entries.append(
                        {
                            "name": storage_name,
                            "type": storage_type,
                            "path": storage_path,
                            "total": total,
                            "avail": avail,
                        }
                    )

                # Get all VMs and their disk configurations
                vms = client.get_node_vms(node_name)
                vm_disks: list[dict[str, Any]] = []
                
                for vm in vms:
                    vmid = vm.get("vmid")
                    vm_name = vm.get("name") or f"VM {vmid}"
                    
                    if vmid is None:
                        continue
                    
                    try:
                        vm_config = client.get_vm_config(node_name, vmid)
                        
                        # Parse disk configurations (scsi0, virtio0, ide0, etc.)
                        for key, value in vm_config.items():
                            if key.startswith(("scsi", "virtio", "ide", "sata")) and "=" in str(value):
                                disk_parts = str(value).split(",")
                                disk_spec = disk_parts[0]

                                # Skip CD/DVD or media entries
                                is_cdrom = any("media=cdrom" in part.lower() for part in disk_parts[1:])
                                if is_cdrom:
                                    continue

                                if ":" in disk_spec:
                                    storage_disk = disk_spec.split(":", 1)
                                    disk_storage = storage_disk[0]
                                    disk_id = storage_disk[1] if len(storage_disk) > 1 else "Unknown"

                                    disk_size = 0
                                    try:
                                        storage_content = client.get_storage_content(node_name, disk_storage)
                                        for item in storage_content:
                                            if (
                                                item.get("content") == "images"
                                                and disk_id in item.get("volid", "")
                                            ):
                                                disk_size = item.get("size", 0)
                                                break
                                    except Exception:
                                        pass

                                    vm_disks.append(
                                        {
                                            "name": f"{key} ({disk_id})",
                                            "size": disk_size,
                                            "storage": disk_storage,
                                            "vm_name": vm_name,
                                            "vmid": vmid,
                                            "disk_id": disk_id,
                                        }
                                    )
                    except Exception:
                        continue

                def update_ui() -> None:
                    # Store raw data
                    raw_storage_entries.clear()
                    raw_storage_entries.extend(storage_entries)
                    raw_vm_disks.clear()
                    raw_vm_disks.extend(vm_disks)
                    
                    # Update filter dropdowns
                    # Update storage type filter
                    storage_types = sorted(set(s.get("type", "") for s in storage_entries if s.get("type")))
                    menu = card1_filter_type_menu["menu"]
                    menu.delete(0, "end")
                    menu.add_command(label="All", command=lambda: card1_filter_type_var.set("All") or apply_filters_and_sort())
                    for stype in storage_types:
                        menu.add_command(label=stype, command=lambda t=stype: card1_filter_type_var.set(t) or apply_filters_and_sort())
                    
                    # Update VM disk storage filter
                    vm_storages = sorted(set(d.get("storage", "") for d in vm_disks if d.get("storage")))
                    menu2 = card2_filter_storage_menu["menu"]
                    menu2.delete(0, "end")
                    menu2.add_command(label="All", command=lambda: card2_filter_storage_var.set("All") or apply_filters_and_sort())
                    for vstorage in vm_storages:
                        menu2.add_command(label=vstorage, command=lambda s=vstorage: card2_filter_storage_var.set(s) or apply_filters_and_sort())
                    
                    # Apply filters and sorting
                    apply_filters_and_sort()

                root.after(0, update_ui)
            except ProxmoxAPIError as exc:
                def show_error() -> None:
                    card1_status.config(text=f"API error: {exc}")
                    card2_status.config(text=f"API error: {exc}")
                    card1_status.pack(pady=20)
                    card2_status.pack(pady=20)
                root.after(0, show_error)
            except Exception as exc:
                def show_error() -> None:
                    card1_status.config(text=f"Error: {exc}")
                    card2_status.config(text=f"Error: {exc}")
                    card1_status.pack(pady=20)
                    card2_status.pack(pady=20)
                root.after(0, show_error)
            finally:
                if client:
                    client.close()

        threading.Thread(target=worker, daemon=True).start()

    tk.Button(
        refresh_frame,
        text="Refresh",
        command=load_data,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.LEFT)

    # Load data on view open
    root.after(100, load_data)

    return frame

