from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from typing import Any

from preferences import get_preference, set_preference
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


def format_duration(seconds: int | None) -> str:
    """Format seconds to human-readable duration."""
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


def show_container_details_window(
    parent: tk.Tk,
    account: dict,
    node_name: str | None,
    vmid: int,
    container_name: str,
    container_runtime: dict[str, Any],
    rows_container: tk.Frame,
    render_container_rows_func,
) -> None:
    """Show detailed container information in the current window."""
    # Clear the rows container
    for child in rows_container.winfo_children():
        child.destroy()
    
    # Create a container for the details view
    details_container = tk.Frame(rows_container, bg=PROXMOX_DARK)
    details_container.pack(fill=tk.BOTH, expand=True)
    
    # Header with back button
    header = tk.Frame(details_container, bg=PROXMOX_DARK)
    header.pack(fill=tk.X, padx=20, pady=(20, 10))
    
    def go_back() -> None:
        """Return to container list view."""
        for child in rows_container.winfo_children():
            child.destroy()
        render_container_rows_func()
    
    tk.Button(
        header,
        text="← Back to Container List",
        command=go_back,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_MEDIUM,
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    ).pack(side=tk.LEFT)
    
    tk.Label(
        header,
        text=container_name,
        font=("Segoe UI", 20, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(20, 0))
    
    status = container_runtime.get("status", "unknown")
    running = str(status).lower() == "running"
    status_color = "#4caf50" if running else "#f44336"
    status_text = "Running" if running else "Stopped"
    
    tk.Label(
        header,
        text=status_text,
        font=("Segoe UI", 12, "bold"),
        fg="white",
        bg=status_color,
        padx=12,
        pady=4,
    ).pack(side=tk.RIGHT, padx=(10, 0))
    
    # Main content with scrollable canvas (no scrollbar)
    canvas = tk.Canvas(details_container, bg=PROXMOX_DARK, highlightthickness=0)
    scrollable_frame = tk.Frame(canvas, bg=PROXMOX_DARK)
    
    def update_scrollregion(event: tk.Event = None) -> None:
        """Update the canvas scroll region."""
        canvas.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
    
    scrollable_frame.bind("<Configure>", update_scrollregion)
    
    canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    
    def configure_canvas(event: tk.Event) -> None:
        """Resize the canvas window when canvas is resized."""
        canvas_width = event.width
        canvas.itemconfig(canvas_window, width=canvas_width)
        update_scrollregion()
    
    canvas.bind("<Configure>", configure_canvas)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    canvas.focus_set()  # Make canvas focusable for mouse wheel
    
    content = tk.Frame(scrollable_frame, bg=PROXMOX_DARK)
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    
    def add_section(title: str) -> tk.Frame:
        """Add a section header and return a frame for content."""
        section_frame = tk.Frame(content, bg=PROXMOX_DARK)
        section_frame.pack(fill=tk.X, pady=(20, 10))
        
        tk.Label(
            section_frame,
            text=title,
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        ).pack(anchor=tk.W)
        
        section_content = tk.Frame(section_frame, bg=PROXMOX_MEDIUM)
        section_content.pack(fill=tk.X, pady=(8, 0))
        
        return section_content
    
    def add_info_row(parent_frame: tk.Frame, label: str, value: str) -> None:
        """Add an info row to a section."""
        row = tk.Frame(parent_frame, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, padx=15, pady=6)
        
        tk.Label(
            row,
            text=f"{label}:",
            font=("Segoe UI", 10, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
            width=20,
            anchor="w",
        ).pack(side=tk.LEFT)
        
        tk.Label(
            row,
            text=value,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
            anchor="w",
            wraplength=700,
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    # Basic Information Section
    basic_section = add_section("Basic Information")
    add_info_row(basic_section, "Container ID", str(vmid))
    add_info_row(basic_section, "Name", container_name)
    add_info_row(basic_section, "Status", status_text)
    add_info_row(basic_section, "Node", node_name or "N/A")
    
    # Runtime Statistics Section
    runtime_section = add_section("Runtime Statistics")
    uptime = container_runtime.get("uptime")
    add_info_row(runtime_section, "Uptime", format_duration(uptime))
    
    cpu_usage = container_runtime.get("cpu", 0)
    add_info_row(runtime_section, "CPU Usage", f"{cpu_usage * 100:.2f}%")
    
    mem_max = container_runtime.get("maxmem")
    mem_used = container_runtime.get("mem")
    if mem_max and mem_used:
        mem_percent = (mem_used / mem_max) * 100 if mem_max > 0 else 0
        add_info_row(
            runtime_section,
            "Memory",
            f"{format_bytes(mem_used)} / {format_bytes(mem_max)} ({mem_percent:.1f}%)",
        )
    else:
        add_info_row(runtime_section, "Memory", format_bytes(mem_max) if mem_max else "N/A")
    
    disk_max = container_runtime.get("maxdisk")
    disk_used = container_runtime.get("disk")
    if disk_max and disk_used:
        disk_percent = (disk_used / disk_max) * 100 if disk_max > 0 else 0
        add_info_row(
            runtime_section,
            "Disk",
            f"{format_bytes(disk_used)} / {format_bytes(disk_max)} ({disk_percent:.1f}%)",
        )
    else:
        add_info_row(runtime_section, "Disk", format_bytes(disk_max) if disk_max else "N/A")
    
    # Network Information Section
    network_section = add_section("Network Information")
    # Containers use net0, net1, etc. in config, but runtime data might have different structure
    networks = container_runtime.get("network", {})
    if networks and isinstance(networks, dict):
        for iface_name, iface_data in networks.items():
            if isinstance(iface_data, dict):
                ip = iface_data.get("ip-address") or iface_data.get("ip") or "N/A"
                mac = iface_data.get("mac-address") or iface_data.get("mac") or "N/A"
                net_info = f"Interface: {iface_name} | IP: {ip} | MAC: {mac}"
                add_info_row(network_section, f"Network {iface_name}", net_info)
            else:
                add_info_row(network_section, f"Network {iface_name}", str(iface_data))
    else:
        add_info_row(network_section, "Networks", "No network information available")
    
    # Loading indicator for detailed config
    loading_label = tk.Label(
        content,
        text="Loading detailed configuration...",
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    loading_label.pack(pady=20)
    
    def load_detailed_config() -> None:
        """Load and display detailed container configuration."""
        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        
        if not all([host, username, password, node_name]):
            loading_label.config(text="Unable to load detailed configuration: missing credentials")
            return
        
        def worker() -> None:
            client: ProxmoxClient | None = None
            container_config: dict[str, Any] | None = None
            error_msg: str | None = None
            
            try:
                client = ProxmoxClient(
                    host=host,
                    username=username,
                    password=password,
                    verify_ssl=verify_ssl,
                    trusted_cert=trusted_cert,
                    trusted_fingerprint=trusted_fp,
                )
                container_config = client.get_container_config(node_name, vmid)
            except ProxmoxAPIError as exc:
                error_msg = f"API error: {exc}"
            except Exception as exc:
                error_msg = f"Error: {exc}"
            finally:
                if client:
                    client.close()
            
            def update_ui() -> None:
                loading_label.destroy()
                
                if error_msg:
                    tk.Label(
                        content,
                        text=f"Error loading configuration: {error_msg}",
                        font=("Segoe UI", 11),
                        fg="#f44336",
                        bg=PROXMOX_DARK,
                    ).pack(pady=20)
                    update_scrollregion()
                    return
                
                if not container_config:
                    return
                
                # Hardware Configuration Section
                hw_section = add_section("Hardware Configuration")
                
                # CPU
                cores = container_config.get("cores", "N/A")
                cpu_units = container_config.get("cpuunits", "N/A")
                cpu_limit = container_config.get("cpulimit", "N/A")
                if cores != "N/A":
                    add_info_row(hw_section, "CPU Cores", str(cores))
                if cpu_units != "N/A":
                    add_info_row(hw_section, "CPU Units", str(cpu_units))
                if cpu_limit != "N/A":
                    add_info_row(hw_section, "CPU Limit", str(cpu_limit))
                
                # Memory
                memory = container_config.get("memory")
                swap = container_config.get("swap")
                if memory:
                    add_info_row(hw_section, "Memory", format_bytes(int(memory)))
                if swap:
                    add_info_row(hw_section, "Swap", format_bytes(int(swap)))
                
                # Root filesystem
                rootfs = container_config.get("rootfs")
                if rootfs:
                    add_info_row(hw_section, "Root Filesystem", str(rootfs))
                
                # Additional storage
                mp_keys = [k for k in container_config.keys() if k.startswith("mp")]
                if mp_keys:
                    for mp_key in sorted(mp_keys):
                        mp_value = container_config.get(mp_key, "")
                        add_info_row(hw_section, f"Mount Point ({mp_key})", str(mp_value))
                
                # Network interfaces (detailed)
                net_keys = [k for k in container_config.keys() if k.startswith("net")]
                if net_keys:
                    for net_key in sorted(net_keys):
                        net_value = container_config.get(net_key, "")
                        add_info_row(hw_section, f"Network ({net_key})", str(net_value))
                
                # Other Configuration Section
                other_section = add_section("Other Configuration")
                
                # OS Type
                ostype = container_config.get("ostype", "N/A")
                add_info_row(other_section, "OS Type", str(ostype))
                
                # Template
                template = container_config.get("template", "N/A")
                if template != "N/A":
                    add_info_row(other_section, "Template", str(template))
                
                # Arch
                arch = container_config.get("arch", "N/A")
                add_info_row(other_section, "Architecture", str(arch))
                
                # Hostname
                hostname = container_config.get("hostname", "N/A")
                add_info_row(other_section, "Hostname", str(hostname))
                
                # Nameserver
                nameserver = container_config.get("nameserver", "N/A")
                add_info_row(other_section, "Nameserver", str(nameserver))
                
                # Search domain
                searchdomain = container_config.get("searchdomain", "N/A")
                if searchdomain != "N/A":
                    add_info_row(other_section, "Search Domain", str(searchdomain))
                
                # Protection
                protection = container_config.get("protection", "N/A")
                add_info_row(other_section, "Protection", str(protection))
                
                # Tags
                tags = container_config.get("tags", "N/A")
                add_info_row(other_section, "Tags", str(tags))
                
                # Description
                description = container_config.get("description", "")
                if description:
                    add_info_row(other_section, "Description", description)
                
                # All other config items
                known_keys = {
                    "cores", "cpuunits", "cpulimit", "memory", "swap", "rootfs",
                    "ostype", "template", "arch", "hostname", "nameserver", "searchdomain",
                    "protection", "tags", "description",
                }
                known_keys.update(mp_keys)
                known_keys.update(net_keys)
                
                other_keys = [k for k in container_config.keys() if k not in known_keys and not k.startswith("unused")]
                if other_keys:
                    extra_section = add_section("Additional Configuration")
                    for key in sorted(other_keys):
                        value = container_config.get(key, "")
                        add_info_row(extra_section, key, str(value))
                
                # Update scroll region after content is added
                parent.after(50, update_scrollregion)
                # Rebind mouse wheel to new content
                bind_mousewheel_to_widget(scrollable_frame)
            
            parent.after(0, update_ui)
        
        threading.Thread(target=worker, daemon=True).start()
    
    # Make mouse wheel work for scrolling
    def on_mousewheel(event: tk.Event) -> None:
        """Handle mouse wheel scrolling on Windows/Mac."""
        if event.delta:
            # Windows/Mac
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"
    
    def on_mousewheel_linux_up(event: tk.Event) -> None:
        """Handle mouse wheel up on Linux."""
        canvas.yview_scroll(-3, "units")
        return "break"
    
    def on_mousewheel_linux_down(event: tk.Event) -> None:
        """Handle mouse wheel down on Linux."""
        canvas.yview_scroll(3, "units")
        return "break"
    
    # Bind mouse wheel events to canvas and all child widgets
    def bind_mousewheel_to_widget(widget: tk.Widget) -> None:
        """Bind mouse wheel events to a widget."""
        widget.bind("<MouseWheel>", on_mousewheel)
        widget.bind("<Button-4>", on_mousewheel_linux_up)
        widget.bind("<Button-5>", on_mousewheel_linux_down)
        # Bind to all children recursively
        for child in widget.winfo_children():
            bind_mousewheel_to_widget(child)
    
    # Bind to canvas and scrollable frame initially
    bind_mousewheel_to_widget(canvas)
    bind_mousewheel_to_widget(scrollable_frame)
    bind_mousewheel_to_widget(details_container)  # Also bind to container
    
    # Ensure canvas gets focus for mouse wheel events
    def ensure_canvas_focus() -> None:
        canvas.focus_set()
        canvas.update_idletasks()
    
    parent.after(150, ensure_canvas_focus)
    
    # Start loading detailed config
    parent.after(100, load_detailed_config)


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
        text="Manage Containers",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 6), padx=40)

    subtitle = tk.Label(
        frame,
        text="Search, review, and control your Proxmox containers.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
    )
    subtitle.pack(anchor=tk.W, padx=40, pady=(0, 10))

    status_var = tk.StringVar(value="")
    search_var = tk.StringVar()

    search_frame = tk.Frame(frame, bg=PROXMOX_DARK)
    search_frame.pack(anchor=tk.CENTER, pady=(10, 20))

    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        width=40,
        font=("Segoe UI", 12),
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        bd=0,
        relief="flat",
        highlightthickness=1,
        highlightcolor=PROXMOX_ORANGE,
        highlightbackground="#363c45",
    )
    search_entry.pack(side=tk.LEFT, padx=(0, 10))

    def clear_search() -> None:
        search_var.set("")

    tk.Button(
        search_frame,
        text="Clear",
        command=clear_search,
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    ).pack(side=tk.LEFT)

    tk.Button(
        search_frame,
        text="Refresh",
        command=lambda: refresh_data(force=True),
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=6,
    ).pack(side=tk.LEFT, padx=(10, 0))

    sort_options = [
        ("Name (A→Z)", "name"),
        ("Name (Z→A)", "name_desc"),
        ("Container ID (ascending)", "id"),
        ("Container ID (descending)", "id_desc"),
        ("Running first", "running"),
        ("Stopped first", "stopped"),
    ]

    label_to_key = {label: key for label, key in sort_options}
    default_sort_label = sort_options[0][0]
    stored_sort_key = get_preference(root, "manage_containers_sort", label_to_key[default_sort_label])
    stored_label = next((label for label, key in sort_options if key == stored_sort_key), default_sort_label)
    sort_var = tk.StringVar(value=stored_label)

    tk.Label(
        search_frame,
        text="Order by:",
        font=("Segoe UI", 11, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(10, 6))

    def on_sort_change(*_args: object) -> None:
        key = label_to_key.get(sort_var.get(), "name")
        set_preference(root, "manage_containers_sort", key)
        render_container_rows()

    sort_dropdown = tk.OptionMenu(
        search_frame,
        sort_var,
        *label_to_key.keys(),
        command=lambda *_: on_sort_change(),
    )

    sort_dropdown.configure(
        font=("Segoe UI", 11),
        bg=PROXMOX_MEDIUM,
        fg=PROXMOX_LIGHT,
        highlightthickness=1,
        highlightbackground="#3a414d",
        activebackground=PROXMOX_ORANGE,
        activeforeground="white",
        width=20,
    )
    sort_dropdown["menu"].configure(font=("Segoe UI", 11), bg="#2f3640", fg=PROXMOX_LIGHT)

    sort_dropdown.pack(side=tk.LEFT)

    # Ensure initial preference is honored after UI is built.
    root.after_idle(on_sort_change)

    list_card = tk.Frame(frame, bg=PROXMOX_MEDIUM)
    list_card.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 0))

    header = tk.Frame(list_card, bg=PROXMOX_MEDIUM)
    header.pack(fill=tk.X, padx=20, pady=(20, 10))
    tk.Label(
        header,
        text="Containers",
        font=("Segoe UI", 16, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)
    tk.Label(
        header,
        textvariable=status_var,
        font=("Segoe UI", 10),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.RIGHT)

    rows_container = tk.Frame(list_card, bg=PROXMOX_MEDIUM)
    rows_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 0))

    data_holder: dict[str, Any] = {"containers": [], "summary": None}

    def styled_confirm(title: str, message: str) -> bool:
        dialog = tk.Toplevel(root)
        dialog.title(title)
        dialog.configure(bg=PROXMOX_DARK)
        dialog.transient(root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text=title,
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        ).pack(anchor=tk.W, padx=25, pady=(20, 6))

        tk.Label(
            dialog,
            text=message,
            font=("Segoe UI", 11),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            wraplength=420,
            justify=tk.LEFT,
        ).pack(fill=tk.X, padx=25, pady=(0, 15))

        response = {"value": False}

        def choose(value: bool) -> None:
            response["value"] = value
            dialog.destroy()

        buttons = tk.Frame(dialog, bg=PROXMOX_DARK)
        buttons.pack(fill=tk.X, padx=25, pady=(0, 20))

        tk.Button(
            buttons,
            text="Cancel",
            command=lambda: choose(False),
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
            buttons,
            text="Confirm",
            command=lambda: choose(True),
            font=("Segoe UI", 11, "bold"),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            activeforeground="white",
            bd=0,
            padx=16,
            pady=8,
        ).pack(side=tk.RIGHT)

        dialog.wait_window()
        return response["value"]

    def filtered_containers() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        containers: list[dict[str, Any]] = list(data_holder.get("containers", []))
        if not term:
            return containers
        filtered: list[dict[str, Any]] = []
        for ct in containers:
            name = str(ct.get("name") or "").lower()
            vmid = str(ct.get("vmid") or "").lower()
            if term in name or term in vmid:
                filtered.append(ct)
        return filtered

    def render_container_rows() -> None:
        for child in rows_container.winfo_children():
            child.destroy()

        containers = filtered_containers()
        if not data_holder.get("summary"):
            tk.Label(
                rows_container,
                text="No Proxmox data loaded yet. Use Refresh to fetch the latest containers.",
                font=("Segoe UI", 12),
                fg="#ffb74d",
                bg=PROXMOX_MEDIUM,
                wraplength=700,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, pady=10)
            return

        if not containers:
            tk.Label(
                rows_container,
                text="No containers match your search.",
                font=("Segoe UI", 12),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.CENTER, pady=20)
            return

        sort_key = label_to_key.get(sort_var.get(), "name")

        def container_name(ct: dict[str, Any]) -> str:
            return str(ct.get("name") or "").lower()

        def container_id(ct: dict[str, Any]) -> int:
            try:
                return int(ct.get("vmid") or 0)
            except (TypeError, ValueError):
                return 0

        def container_running_weight(ct: dict[str, Any]) -> int:
            status = str(ct.get("status", "")).lower()
            return 0 if status == "running" else 1

        if sort_key == "name":
            containers.sort(key=lambda ct: (container_name(ct), container_id(ct)))
        elif sort_key == "name_desc":
            containers.sort(key=lambda ct: (container_name(ct), container_id(ct)), reverse=True)
        elif sort_key == "id":
            containers.sort(key=lambda ct: (container_id(ct), container_name(ct)))
        elif sort_key == "id_desc":
            containers.sort(key=lambda ct: (container_id(ct), container_name(ct)), reverse=True)
        elif sort_key == "running":
            containers.sort(key=lambda ct: (container_running_weight(ct), container_name(ct)))
        elif sort_key == "stopped":
            containers.sort(key=lambda ct: (1 - container_running_weight(ct), container_name(ct)))
        else:
            containers.sort(key=lambda ct: (container_name(ct), container_id(ct)))

        for ct in containers:
            render_container_row(ct)

    def perform_container_action(action: str, ct: dict[str, Any]) -> None:
        account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
        summary = data_holder.get("summary")
        if not account or not summary:
            messagebox.showerror("Unavailable", "Account or container data is not ready yet.", parent=root)
            return

        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        node_name = getattr(summary, "node_name", None) or ct.get("node")

        if not all([host, username, password, node_name]):
            messagebox.showerror(
                "Missing information",
                "Incomplete connection details or node information.",
                parent=root,
            )
            return

        name = ct.get("name") or f"Container {ct.get('vmid')}"
        vmid = ct.get("vmid")
        if vmid is None:
            messagebox.showerror("Unknown Container", "Unable to determine the container ID.", parent=root)
            return

        confirmations = {
            "stop": f"Are you sure you want to stop {name}?",
            "restart": f"Restart {name}? This will reboot the container.",
        }
        if action in confirmations:
            if not styled_confirm("Confirm action", confirmations[action]):
                return

        status_var.set(f"{action.capitalize()} request submitted for {name}...")

        def worker() -> None:
            client: ProxmoxClient | None = None
            message = ""
            try:
                client = ProxmoxClient(
                    host=host,
                    username=username,
                    password=password,
                    verify_ssl=verify_ssl,
                    trusted_cert=trusted_cert,
                    trusted_fingerprint=trusted_fp,
                )
                if action == "start":
                    client.start_container(node_name, vmid)
                    message = f"{name} is starting."
                elif action == "stop":
                    client.stop_container(node_name, vmid)
                    message = f"{name} is stopping."
                else:
                    client.reboot_container(node_name, vmid)
                    message = f"{name} is restarting."
            except ProxmoxAPIError as exc:
                message = f"API error: {exc}"
            except Exception as exc:  # pragma: no cover
                message = f"Unexpected error: {exc}"
            finally:
                if client:
                    client.close()

            def finalize() -> None:
                status_var.set(message)
                # Wait a moment for the container action to complete, then force refresh
                root.after(1000, lambda: refresh_data(force=True))
                root.after(3000, lambda: refresh_data(force=True))  # Second refresh after 3 seconds
                # Also trigger dashboard refresh for consistency
                refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
                if callable(refresh_cb):
                    refresh_cb(mode="full", force=True)

            root.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()

    def render_container_row(ct: dict[str, Any]) -> None:
        row = tk.Frame(rows_container, bg=PROXMOX_MEDIUM, highlightthickness=1, highlightbackground="#3c434e")
        row.pack(fill=tk.X, pady=6)

        info = tk.Frame(row, bg=PROXMOX_MEDIUM)
        info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=12)

        name = ct.get("name") or f"Container {ct.get('vmid')}"
        tk.Label(
            info,
            text=name,
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(anchor=tk.W)

        tk.Label(
            info,
            text=f"CTID: {ct.get('vmid', 'N/A')}",
            font=("Segoe UI", 11),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(anchor=tk.W, pady=(2, 0))

        status = ct.get("status", "unknown")
        running = str(status).lower() == "running"
        status_color = "#4caf50" if running else "#f44336"
        status_text = "Running" if running else "Stopped"

        status_badge = tk.Label(
            row,
            text=status_text,
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=status_color,
            padx=14,
            pady=6,
        )
        status_badge.pack(side=tk.LEFT, padx=(0, 10))

        actions = tk.Frame(row, bg=PROXMOX_MEDIUM)
        actions.pack(side=tk.RIGHT, padx=10, pady=12)

        def action_button(label: str, command, enabled: bool) -> None:
            tk.Button(
                actions,
                text=label,
                command=command,
                font=("Segoe UI", 10, "bold"),
                state=tk.NORMAL if enabled else tk.DISABLED,
                bg=PROXMOX_ORANGE if enabled else "#555a63",
                fg="white",
                activebackground="#ff8126",
                activeforeground="white",
                bd=0,
                padx=12,
                pady=6,
            ).pack(side=tk.LEFT, padx=4)

        action_button("Start", lambda ct=ct: perform_container_action("start", ct), not running)
        action_button("Stop", lambda ct=ct: perform_container_action("stop", ct), running)
        action_button("Restart", lambda ct=ct: perform_container_action("restart", ct), running)

        def open_console(ct_obj: dict[str, Any]) -> None:
            """Launch the container console in a separate viewer window."""
            account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
            summary_obj = data_holder.get("summary")
            if not account or not summary_obj:
                messagebox.showerror("Unavailable", "Account or container data is not ready yet.", parent=root)
                return

            vmid = ct_obj.get("vmid")
            if vmid is None:
                messagebox.showerror("Unknown Container", "Unable to determine the container ID.", parent=root)
                return

            container_name = ct_obj.get("name") or f"Container {vmid}"
            container_status = str(ct_obj.get("status", "")).lower()

            if container_status != "running":
                if not styled_confirm(
                    "Start Container",
                    f"The container '{container_name}' is not running. Start it now to open the console?",
                ):
                    return

                status_var.set(f"Starting {container_name}...")

                def start_container_worker() -> None:
                    proxmox_cfg = _get_active_proxmox_config(account) or {}
                    host = proxmox_cfg.get("host")
                    username = proxmox_cfg.get("username")
                    password = proxmox_cfg.get("password")
                    verify_ssl = proxmox_cfg.get("verify_ssl", False)
                    trusted_cert = proxmox_cfg.get("trusted_cert")
                    trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
                    node_name = getattr(summary_obj, "node_name", None) or ct_obj.get("node")

                    if not all([host, username, password, node_name]):
                        def show_missing() -> None:
                            messagebox.showerror(
                                "Missing information",
                                "Incomplete connection or node details prevent starting this container.",
                                parent=root,
                            )
                            status_var.set("Unable to start the container.")
                        root.after(0, show_missing)
                        return

                    client: ProxmoxClient | None = None
                    error_message = ""
                    try:
                        client = ProxmoxClient(
                            host=host,
                            username=username,
                            password=password,
                            verify_ssl=verify_ssl,
                            trusted_cert=trusted_cert,
                            trusted_fingerprint=trusted_fp,
                        )
                        client.start_container(node_name, vmid)
                    except Exception as exc:
                        error_message = str(exc)
                    finally:
                        if client:
                            client.close()

                    def finalize_start() -> None:
                        if error_message:
                            messagebox.showerror("Start Container error", f"Failed to start container: {error_message}", parent=root)
                            status_var.set(f"Failed to start {container_name}.")
                        else:
                            status_var.set(f"{container_name} is starting. Opening console once it is ready...")
                            root.after(
                                4000,
                                lambda: launch_container_console(
                                    root,
                                    ct_obj,
                                    summary_obj,
                                    status_callback=status_var.set,
                                ),
                            )

                    root.after(0, finalize_start)

                threading.Thread(target=start_container_worker, daemon=True).start()
                return

            launch_container_console(root, ct_obj, summary_obj, status_callback=status_var.set)

        def launch_container_console(
            root: tk.Tk,
            ct_obj: dict[str, Any],
            summary_obj: Any,
            status_callback: Any = None,
        ) -> None:
            """Launch container console using SSH terminal."""
            account = getattr(root, "app_state", {}).get("account")
            if not account:
                if status_callback:
                    status_callback("No account available.")
                return

            proxmox_cfg = _get_active_proxmox_config(account) or {}
            host = proxmox_cfg.get("host")
            username = proxmox_cfg.get("username")
            password = proxmox_cfg.get("password")
            node_name = getattr(summary_obj, "node_name", None) or ct_obj.get("node")
            vmid = ct_obj.get("vmid")

            if not all([host, username, password, node_name, vmid]):
                if status_callback:
                    status_callback("Missing connection details.")
                return

            def update_status(msg: str) -> None:
                if status_callback:
                    try:
                        status_callback(msg)
                    except Exception:
                        pass

            container_name = ct_obj.get("name") or f"Container {vmid}"
            
            # Extract hostname from host URL for SSH
            from urllib.parse import urlparse
            parsed = urlparse(host)
            ssh_host = parsed.hostname or host.split("://")[-1].split(":")[0] if "://" in host else host
            # SSH always uses port 22 (not the HTTPS port from the URL)
            ssh_port = 22
            
            # Extract username (remove @realm if present)
            ssh_username = username.split("@")[0] if "@" in username else username
            
            update_status(f"Opening SSH terminal for {container_name}...")
            
            # Launch external terminal with SSH connection to Proxmox host, then enter container
            import shutil
            import subprocess
            
            # Find available terminal emulator
            terminal_cmd = None
            for term in ["gnome-terminal", "xterm", "konsole", "xfce4-terminal", "mate-terminal", "lxterminal"]:
                if shutil.which(term):
                    terminal_cmd = term
                    break
            
            if not terminal_cmd:
                messagebox.showerror(
                    "Terminal Required",
                    "No terminal emulator found.\n\n"
                    "Please install one of:\n"
                    "• gnome-terminal\n"
                    "• xterm\n"
                    "• konsole\n"
                    "• xfce4-terminal",
                    parent=root,
                )
                update_status("No terminal emulator found.")
                return
            
            # Build SSH command to connect to Proxmox host and enter container
            # Use 'pct enter' (preferred) or fallback to 'lxc-attach'
            # The -t flag allocates a pseudo-terminal for interactive use
            # Add error checking and diagnostics
            ssh_command = (
                f"ssh -t -p {ssh_port} {ssh_username}@{ssh_host} "
                f"'"
                f"echo \"Checking container {vmid} status...\"; "
                f"if pct status {vmid} 2>&1 | grep -q running; then "
                f"  echo \"Container is running. Entering container...\"; "
                f"  pct enter {vmid} 2>&1 || (echo \"pct enter failed, trying lxc-attach...\"; lxc-attach -n {vmid} 2>&1) || "
                f"  (echo \"Failed to enter container. You are now in a shell on the Proxmox host.\"; exec bash -l); "
                f"else "
                f"  echo \"Container {vmid} is not running. Start it first with: pct start {vmid}\"; "
                f"  echo \"You are now in a shell on the Proxmox host.\"; "
                f"  exec bash -l; "
                f"fi"
                f"'"
            )
            
            # Launch terminal with SSH command
            # Run SSH directly - it will handle the interactive session
            try:
                if terminal_cmd == "gnome-terminal":
                    subprocess.Popen([
                        "gnome-terminal",
                        "--title", f"{container_name} - Container Console",
                        "--",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                elif terminal_cmd == "xterm":
                    subprocess.Popen([
                        "xterm",
                        "-T", f"{container_name} - Container Console",
                        "-e",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                elif terminal_cmd == "konsole":
                    subprocess.Popen([
                        "konsole",
                        "--title", f"{container_name} - Container Console",
                        "-e",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                elif terminal_cmd == "xfce4-terminal":
                    subprocess.Popen([
                        "xfce4-terminal",
                        "-T", f"{container_name} - Container Console",
                        "-e",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                elif terminal_cmd == "mate-terminal":
                    subprocess.Popen([
                        "mate-terminal",
                        "--title", f"{container_name} - Container Console",
                        "-e",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                elif terminal_cmd == "lxterminal":
                    subprocess.Popen([
                        "lxterminal",
                        "-t", f"{container_name} - Container Console",
                        "-e",
                        "bash",
                        "-c",
                        f"echo 'Connecting to {container_name} (CT {vmid})...'; {ssh_command}; echo 'Connection closed. Press Enter to exit...'; read"
                    ])
                else:
                    # Fallback: try to run the command directly
                    subprocess.Popen(["bash", "-c", ssh_command])
                
                update_status(f"SSH terminal opened for {container_name}. Enter password when prompted.")
                
                # Show a helpful message about SSH password
                def show_ssh_info() -> None:
                    try:
                        dialog = tk.Toplevel(root)
                        dialog.title("SSH Connection")
                        dialog.configure(bg=PROXMOX_DARK)
                        dialog.transient(root)
                        dialog.resizable(False, False)
                        
                        try:
                            dialog.attributes("-topmost", True)
                        except Exception:
                            pass

                        tk.Label(
                            dialog,
                            text="SSH Terminal Opened",
                            font=("Segoe UI", 14, "bold"),
                            fg=PROXMOX_ORANGE,
                            bg=PROXMOX_DARK,
                        ).pack(padx=24, pady=(20, 6))

                        message = (
                            f"A terminal window has been opened to connect to {container_name}.\n\n"
                            "You will be prompted for your SSH password.\n"
                            "Enter the same password you use for Proxmox API access.\n\n"
                            "The terminal will automatically enter the container\n"
                            "once the SSH connection is established."
                        )
                        
                        tk.Label(
                            dialog,
                            text=message,
                            font=("Segoe UI", 11),
                            fg=PROXMOX_LIGHT,
                            bg=PROXMOX_DARK,
                            wraplength=450,
                            justify=tk.LEFT,
                        ).pack(padx=24, pady=(0, 16))

                        tk.Button(
                            dialog,
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
                        ).pack(padx=24, pady=(0, 20))
                    except Exception:
                        pass
                
                root.after(500, show_ssh_info)
                
            except Exception as exc:
                update_status(f"Error opening terminal: {exc}")
                messagebox.showerror(
                    "Terminal Error",
                    f"Failed to open terminal:\n{exc}\n\n"
                    "Make sure you have a terminal emulator installed and\n"
                    "SSH access is configured on your Proxmox host.",
                    parent=root,
                )

        def view_container_details(ct_obj: dict[str, Any]) -> None:
            """Open a detailed container information window."""
            account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
            summary_obj = data_holder.get("summary")
            if not account or not summary_obj:
                messagebox.showerror("Unavailable", "Account or container data is not ready yet.", parent=root)
                return
            
            vmid = ct_obj.get("vmid")
            if vmid is None:
                messagebox.showerror("Unknown Container", "Unable to determine the container ID.", parent=root)
                return
            
            container_name = ct_obj.get("name") or f"Container {vmid}"
            node_name = getattr(summary_obj, "node_name", None) or ct_obj.get("node")
            
            # Show detailed container info in current window
            show_container_details_window(root, account, node_name, vmid, container_name, ct_obj, rows_container, render_container_rows)
        
        action_button("Open Console", lambda ct=ct: open_console(ct), True)
        action_button("View Info", lambda ct=ct: view_container_details(ct), True)

    def refresh_data(force: bool = False) -> None:
        app_state = getattr(root, "app_state", None)
        account = app_state.get("account") if isinstance(app_state, dict) else None
        
        if force and account:
            # Force refresh: fetch data directly from Proxmox
            status_var.set("Requesting latest container data...")
            
            def fetch_worker() -> None:
                proxmox_cfg = _get_active_proxmox_config(account) or {}
                host = proxmox_cfg.get("host")
                username = proxmox_cfg.get("username")
                password = proxmox_cfg.get("password")
                verify_ssl = proxmox_cfg.get("verify_ssl", False)
                trusted_cert = proxmox_cfg.get("trusted_cert")
                trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
                
                if not all([host, username, password]):
                    def show_error() -> None:
                        status_var.set("Unable to connect: missing credentials.")
                    root.after(0, show_error)
                    return
                
                client: ProxmoxClient | None = None
                try:
                    from proxmox_client import ProxmoxSummary
                    client = ProxmoxClient(
                        host=host,
                        username=username,
                        password=password,
                        verify_ssl=verify_ssl,
                        trusted_cert=trusted_cert,
                        trusted_fingerprint=trusted_fp,
                    )
                    summary = client.fetch_summary()
                    
                    def update_ui() -> None:
                        containers = getattr(summary, "containers", None)
                        if containers is None and isinstance(summary, dict):
                            containers = summary.get("containers")
                        
                        data_holder["summary"] = summary
                        data_holder["containers"] = list(containers or [])
                        status_var.set(f"{len(data_holder['containers'])} containers loaded.")
                        render_container_rows()
                        
                        # Also update dashboard data for consistency
                        if isinstance(app_state, dict):
                            if "dashboard_data" not in app_state:
                                app_state["dashboard_data"] = {}
                            app_state["dashboard_data"]["summary"] = summary
                        
                        dock_refresh = getattr(root, "refresh_dock_panel", None)
                        if callable(dock_refresh):
                            root.after_idle(dock_refresh)
                    
                    root.after(0, update_ui)
                except ProxmoxAPIError as exc:
                    def show_error() -> None:
                        status_var.set(f"API error: {exc}")
                    root.after(0, show_error)
                except Exception as exc:
                    def show_error() -> None:
                        status_var.set(f"Error: {exc}")
                    root.after(0, show_error)
                finally:
                    if client:
                        client.close()
            
            threading.Thread(target=fetch_worker, daemon=True).start()
            return
        
        # Non-force refresh: use cached dashboard data
        summary = None
        if isinstance(app_state, dict):
            dashboard_data = app_state.get("dashboard_data") or {}
            summary = dashboard_data.get("summary")

        if summary is None:
            status_var.set("No container data available. Use Refresh to load from Proxmox.")
            data_holder["summary"] = None
            data_holder["containers"] = []
            render_container_rows()
            return

        containers = getattr(summary, "containers", None)
        if containers is None and isinstance(summary, dict):
            containers = summary.get("containers")

        data_holder["summary"] = summary
        data_holder["containers"] = list(containers or [])
        status_var.set(f"{len(data_holder['containers'])} containers loaded.")
        render_container_rows()
        dock_refresh = getattr(root, "refresh_dock_panel", None)
        if callable(dock_refresh):
            root.after_idle(dock_refresh)

    search_var.trace_add("write", lambda *_: render_container_rows())
    refresh_data()
    search_entry.focus_set()

    return frame
