from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any

from preferences import get_preference, set_preference
from proxmox_client import ProxmoxAPIError, ProxmoxClient
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE
from vm_console_launcher import launch_vm_console


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


def show_vm_details_window(
    parent: tk.Tk,
    account: dict,
    node_name: str | None,
    vmid: int,
    vm_name: str,
    vm_runtime: dict[str, Any],
    rows_container: tk.Frame,
    render_vm_rows_func,
) -> None:
    """Show detailed VM information in the current window."""
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
        """Return to VM list view."""
        for child in rows_container.winfo_children():
            child.destroy()
        render_vm_rows_func()
    
    tk.Button(
        header,
        text="← Back to VM List",
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
        text=vm_name,
        font=("Segoe UI", 20, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(20, 0))
    
    status = vm_runtime.get("status", "unknown")
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
    add_info_row(basic_section, "VM ID", str(vmid))
    add_info_row(basic_section, "Name", vm_name)
    add_info_row(basic_section, "Status", status_text)
    add_info_row(basic_section, "Node", node_name or "N/A")
    
    # Runtime Statistics Section
    runtime_section = add_section("Runtime Statistics")
    uptime = vm_runtime.get("uptime")
    add_info_row(runtime_section, "Uptime", format_duration(uptime))
    
    cpu_usage = vm_runtime.get("cpu", 0)
    add_info_row(runtime_section, "CPU Usage", f"{cpu_usage * 100:.2f}%")
    
    mem_max = vm_runtime.get("maxmem")
    mem_used = vm_runtime.get("mem")
    if mem_max and mem_used:
        mem_percent = (mem_used / mem_max) * 100 if mem_max > 0 else 0
        add_info_row(
            runtime_section,
            "Memory",
            f"{format_bytes(mem_used)} / {format_bytes(mem_max)} ({mem_percent:.1f}%)",
        )
    else:
        add_info_row(runtime_section, "Memory", format_bytes(mem_max) if mem_max else "N/A")
    
    disk_max = vm_runtime.get("maxdisk")
    disk_used = vm_runtime.get("disk")
    if disk_max and disk_used:
        disk_percent = (disk_used / disk_max) * 100 if disk_max > 0 else 0
        add_info_row(
            runtime_section,
            "Disk",
            f"{format_bytes(disk_used)} / {format_bytes(disk_max)} ({disk_percent:.1f}%)",
        )
    else:
        add_info_row(runtime_section, "Disk", format_bytes(disk_max) if disk_max else "N/A")
    
    pid = vm_runtime.get("pid")
    add_info_row(runtime_section, "Process ID", str(pid) if pid else "N/A")
    
    # Network Information Section
    network_section = add_section("Network Information")
    networks = vm_runtime.get("network", [])
    if networks:
        for idx, net in enumerate(networks):
            net_name = net.get("name", f"net{idx}")
            bridge = net.get("bridge", "N/A")
            mac = net.get("mac", "N/A")
            model = net.get("model", "N/A")
            tag = net.get("tag", "")
            firewall = net.get("firewall", "")
            rate = net.get("rate", "")
            
            net_info = f"Interface: {net_name}"
            if model != "N/A":
                net_info += f" | Model: {model}"
            net_info += f" | Bridge: {bridge}"
            net_info += f" | MAC: {mac}"
            if tag:
                net_info += f" | VLAN Tag: {tag}"
            if firewall:
                net_info += f" | Firewall: {firewall}"
            if rate:
                net_info += f" | Rate Limit: {rate}"
            
            add_info_row(network_section, f"Network {idx + 1}", net_info)
    else:
        add_info_row(network_section, "Networks", "No network interfaces configured")
    
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
        """Load and display detailed VM configuration."""
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
            vm_config: dict[str, Any] | None = None
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
                vm_config = client.get_vm_config(node_name, vmid)
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
                
                if not vm_config:
                    return
                
                # Hardware Configuration Section
                hw_section = add_section("Hardware Configuration")
                
                # CPU
                cores = vm_config.get("cores", "N/A")
                sockets = vm_config.get("sockets", "N/A")
                cpu_type = vm_config.get("cpu", "N/A")
                if cores != "N/A" and sockets != "N/A":
                    add_info_row(hw_section, "CPU", f"{cores} cores, {sockets} sockets")
                else:
                    add_info_row(hw_section, "CPU Cores", str(cores))
                    add_info_row(hw_section, "CPU Sockets", str(sockets))
                add_info_row(hw_section, "CPU Type", str(cpu_type))
                
                # Memory
                memory = vm_config.get("memory")
                if memory:
                    add_info_row(hw_section, "Memory", format_bytes(int(memory)))
                
                # Disks
                disk_keys = [k for k in vm_config.keys() if k.startswith(("scsi", "virtio", "ide", "sata"))]
                if disk_keys:
                    for disk_key in sorted(disk_keys):
                        disk_value = vm_config.get(disk_key, "")
                        add_info_row(hw_section, f"Disk ({disk_key})", str(disk_value))
                else:
                    add_info_row(hw_section, "Disks", "No disks configured")
                
                # Network interfaces (detailed)
                net_keys = [k for k in vm_config.keys() if k.startswith("net")]
                if net_keys:
                    for net_key in sorted(net_keys):
                        net_value = vm_config.get(net_key, "")
                        add_info_row(hw_section, f"Network ({net_key})", str(net_value))
                
                # BIOS/Boot
                bios = vm_config.get("bios", "N/A")
                add_info_row(hw_section, "BIOS", str(bios))
                boot = vm_config.get("boot", "N/A")
                add_info_row(hw_section, "Boot Order", str(boot))
                
                # Display/Graphics
                vga = vm_config.get("vga", "N/A")
                add_info_row(hw_section, "VGA", str(vga))
                
                # Other Configuration Section
                other_section = add_section("Other Configuration")
                
                # OS Type
                ostype = vm_config.get("ostype", "N/A")
                add_info_row(other_section, "OS Type", str(ostype))
                
                # Machine
                machine = vm_config.get("machine", "N/A")
                add_info_row(other_section, "Machine Type", str(machine))
                
                # Agent
                agent = vm_config.get("agent", "N/A")
                add_info_row(other_section, "QEMU Agent", str(agent))
                
                # Hotplug
                hotplug = vm_config.get("hotplug", "N/A")
                add_info_row(other_section, "Hotplug", str(hotplug))
                
                # Protection
                protection = vm_config.get("protection", "N/A")
                add_info_row(other_section, "Protection", str(protection))
                
                # Tags
                tags = vm_config.get("tags", "N/A")
                add_info_row(other_section, "Tags", str(tags))
                
                # Description
                description = vm_config.get("description", "")
                if description:
                    add_info_row(other_section, "Description", description)
                
                # All other config items
                known_keys = {
                    "cores", "sockets", "cpu", "memory", "bios", "boot", "vga",
                    "ostype", "machine", "agent", "hotplug", "protection", "tags", "description",
                }
                known_keys.update(disk_keys)
                known_keys.update(net_keys)
                
                other_keys = [k for k in vm_config.keys() if k not in known_keys and not k.startswith("unused")]
                if other_keys:
                    extra_section = add_section("Additional Configuration")
                    for key in sorted(other_keys):
                        value = vm_config.get(key, "")
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
        text="Manage Virtual Machines",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 6), padx=40)

    subtitle = tk.Label(
        frame,
        text="Search, review, and control your Proxmox virtual machines.",
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
        ("VM ID (ascending)", "id"),
        ("VM ID (descending)", "id_desc"),
        ("Running first", "running"),
        ("Stopped first", "stopped"),
    ]

    label_to_key = {label: key for label, key in sort_options}
    default_sort_label = sort_options[0][0]
    stored_sort_key = get_preference(root, "manage_vms_sort", label_to_key[default_sort_label])
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
        set_preference(root, "manage_vms_sort", key)
        render_vm_rows()

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
        text="Virtual Machines",
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

    data_holder: dict[str, Any] = {"vms": [], "summary": None}

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

    def styled_warning(title: str, message: str) -> None:
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

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            font=("Segoe UI", 10, "bold"),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            activeforeground="white",
            bd=0,
            padx=16,
            pady=6,
        ).pack(padx=25, pady=(0, 20))

        dialog.wait_window()

    def filtered_vms() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        vms: list[dict[str, Any]] = list(data_holder.get("vms", []))
        if not term:
            return vms
        filtered: list[dict[str, Any]] = []
        for vm in vms:
            name = str(vm.get("name") or "").lower()
            vmid = str(vm.get("vmid") or "").lower()
            if term in name or term in vmid:
                filtered.append(vm)
        return filtered

    def render_vm_rows() -> None:
        for child in rows_container.winfo_children():
            child.destroy()

        vms = filtered_vms()
        if not data_holder.get("summary"):
            tk.Label(
                rows_container,
                text="No Proxmox data loaded yet. Use Refresh to fetch the latest virtual machines.",
                font=("Segoe UI", 12),
                fg="#ffb74d",
                bg=PROXMOX_MEDIUM,
                wraplength=700,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, pady=10)
            return

        if not vms:
            tk.Label(
                rows_container,
                text="No virtual machines match your search.",
                font=("Segoe UI", 12),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.CENTER, pady=20)
            return

        sort_key = label_to_key.get(sort_var.get(), "name")

        def vm_name(vm: dict[str, Any]) -> str:
            return str(vm.get("name") or "").lower()

        def vm_id(vm: dict[str, Any]) -> int:
            try:
                return int(vm.get("vmid") or 0)
            except (TypeError, ValueError):
                return 0

        def vm_running_weight(vm: dict[str, Any]) -> int:
            status = str(vm.get("status", "")).lower()
            return 0 if status == "running" else 1

        if sort_key == "name":
            vms.sort(key=lambda vm: (vm_name(vm), vm_id(vm)))
        elif sort_key == "name_desc":
            vms.sort(key=lambda vm: (vm_name(vm), vm_id(vm)), reverse=True)
        elif sort_key == "id":
            vms.sort(key=lambda vm: (vm_id(vm), vm_name(vm)))
        elif sort_key == "id_desc":
            vms.sort(key=lambda vm: (vm_id(vm), vm_name(vm)), reverse=True)
        elif sort_key == "running":
            vms.sort(key=lambda vm: (vm_running_weight(vm), vm_name(vm)))
        elif sort_key == "stopped":
            vms.sort(key=lambda vm: (1 - vm_running_weight(vm), vm_name(vm)))
        else:
            vms.sort(key=lambda vm: (vm_name(vm), vm_id(vm)))

        for vm in vms:
            render_vm_row(vm)

    def perform_vm_action(action: str, vm: dict[str, Any]) -> None:
        account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
        summary = data_holder.get("summary")
        if not account or not summary:
            messagebox.showerror("Unavailable", "Account or VM data is not ready yet.", parent=root)
            return

        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        node_name = getattr(summary, "node_name", None) or vm.get("node")

        if not all([host, username, password, node_name]):
            messagebox.showerror(
                "Missing information",
                "Incomplete connection details or node information.",
                parent=root,
            )
            return

        name = vm.get("name") or f"VM {vm.get('vmid')}"
        vmid = vm.get("vmid")
        if vmid is None:
            messagebox.showerror("Unknown VM", "Unable to determine the VM ID.", parent=root)
            return

        confirmations = {
            "stop": f"Are you sure you want to stop {name}?",
            "restart": f"Restart {name}? This will reboot the VM.",
        }
        if action in confirmations:
            if not styled_confirm("Confirm action", confirmations[action]):
                return

        status_var.set(f"{action.capitalize()} request submitted for {name}...")

        def worker() -> None:
            client: ProxmoxClient | None = None
            message = ""
            pci_conflict_detected = False
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
                    # Proactively check for PCI device conflicts before starting
                    try:
                        vm_config = client.get_vm_config(node_name, vmid)
                        all_vms = client.get_node_vms(node_name)
                        pci_conflicts: list[tuple[str, int]] = []
                        
                        for key, value in vm_config.items():
                            if key.startswith("hostpci") and isinstance(value, str):
                                # Extract PCI ID from value
                                if "host=" in value:
                                    pci_id = value.split("host=")[1].split(",")[0].strip()
                                else:
                                    pci_id = value.split(",")[0].strip()
                                
                                # Check if this PCI device is used by other running VMs
                                for vm in all_vms:
                                    other_vmid = vm.get("vmid")
                                    if other_vmid and other_vmid != vmid and vm.get("status") == "running":
                                        try:
                                            other_config = client.get_vm_config(node_name, other_vmid)
                                            for other_key, other_value in other_config.items():
                                                if other_key.startswith("hostpci") and isinstance(other_value, str):
                                                    if "host=" in other_value:
                                                        other_pci_id = other_value.split("host=")[1].split(",")[0].strip()
                                                    else:
                                                        other_pci_id = other_value.split(",")[0].strip()
                                                    # Check if PCI IDs match (including functions)
                                                    if other_pci_id == pci_id or other_pci_id.startswith(pci_id.split(".")[0] + ".") or pci_id.startswith(other_pci_id.split(".")[0] + "."):
                                                        pci_conflicts.append((pci_id, other_vmid))
                                        except Exception:
                                            pass
                        
                        if pci_conflicts:
                            conflict_messages = []
                            for pci_id, conflict_vmid in pci_conflicts:
                                conflict_messages.append(f"PCI device {pci_id} is in use by running VM {conflict_vmid}")
                            
                            pci_conflict_detected = True
                            
                            def show_conflict() -> None:
                                from main import styled_warning
                                styled_warning(
                                    "PCI Device Conflict",
                                    f"Cannot start VM {name} (ID: {vmid}) because the following PCI devices are already in use by other running VMs:\n\n" + "\n".join(conflict_messages) + "\n\nPlease stop the other VMs first or remove the PCI devices from this VM.",
                                    root
                                )
                                status_var.set(f"Cannot start {name} - PCI device conflict.")
                            root.after(0, show_conflict)
                            return
                    except Exception:
                        pass  # If conflict check fails, continue with start attempt
                    
                    try:
                        client.start_vm(node_name, vmid)
                        message = f"{name} is starting."
                    except ProxmoxAPIError as exc:
                        # Get full error text - ProxmoxAPIError includes details in the message
                        full_error_text = str(exc)
                        # Also check args in case details are there
                        if hasattr(exc, "args") and exc.args:
                            full_error_text += " " + " ".join(str(arg) for arg in exc.args)
                        
                        # Check if this is a PCI device conflict error
                        import re
                        pci_conflict_patterns = [
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by VMID\s+['\"]?(\d+)['\"]?",
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by\s+VMID\s+['\"]?(\d+)['\"]?",
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+is already in use by VMID\s+['\"]?(\d+)['\"]?",
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use",
                        ]
                        
                        pci_conflict_match = None
                        for pattern in pci_conflict_patterns:
                            pci_conflict_match = re.search(pattern, full_error_text, re.IGNORECASE)
                            if pci_conflict_match:
                                break
                        
                        if pci_conflict_match:
                            pci_device = pci_conflict_match.group(1) if len(pci_conflict_match.groups()) >= 1 else "unknown"
                            conflict_vmid = pci_conflict_match.group(2) if len(pci_conflict_match.groups()) >= 2 else "unknown"
                            
                            pci_conflict_detected = True
                            
                            def show_pci_conflict() -> None:
                                from main import styled_warning
                                if conflict_vmid != "unknown":
                                    styled_warning(
                                        "PCI Device Conflict",
                                        f"Cannot start VM {name} (ID: {vmid}) because PCI device '{pci_device}' is already in use by VM {conflict_vmid}.\n\n"
                                        f"Please stop VM {conflict_vmid} first if you want to use this PCI device on this VM.",
                                        root
                                    )
                                    status_var.set(f"Cannot start {name} - PCI device '{pci_device}' is in use by VM {conflict_vmid}.")
                                else:
                                    styled_warning(
                                        "PCI Device Conflict",
                                        f"Cannot start VM {name} (ID: {vmid}) because PCI device '{pci_device}' is already in use by another VM.\n\n"
                                        f"Please stop the other VM first if you want to use this PCI device on this VM.",
                                        root
                                    )
                                    status_var.set(f"Cannot start {name} - PCI device '{pci_device}' is in use by another VM.")
                            root.after(0, show_pci_conflict)
                            return
                        # Fallback: check if error mentions PCI device conflict even if regex doesn't match
                        elif "PCI device" in full_error_text.lower() and "already in use" in full_error_text.lower():
                            pci_conflict_detected = True
                            def show_pci_conflict_generic() -> None:
                                from main import styled_warning
                                styled_warning(
                                    "PCI Device Conflict",
                                    f"Cannot start VM {name} (ID: {vmid}) because a PCI device is already in use by another VM.\n\n"
                                    f"Please stop the other VM first if you want to use this PCI device on this VM.",
                                    root
                                )
                                status_var.set(f"Cannot start {name} - PCI device conflict detected.")
                            root.after(0, show_pci_conflict_generic)
                            return
                        else:
                            message = f"API error: {exc}"
                elif action == "stop":
                    client.stop_vm(node_name, vmid)
                    message = f"{name} is stopping."
                else:
                    client.reboot_vm(node_name, vmid)
                    message = f"{name} is restarting."
            except ProxmoxAPIError as exc:
                # Also check outer exception handler for PCI conflicts
                if action == "start" and not pci_conflict_detected:
                    full_error_text = str(exc)
                    if hasattr(exc, "args") and exc.args:
                        full_error_text += " " + " ".join(str(arg) for arg in exc.args)
                    
                    import re
                    pci_conflict_patterns = [
                        r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by VMID\s+['\"]?(\d+)['\"]?",
                        r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by\s+VMID\s+['\"]?(\d+)['\"]?",
                        r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+is already in use by VMID\s+['\"]?(\d+)['\"]?",
                        r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use",
                    ]
                    
                    pci_conflict_match = None
                    for pattern in pci_conflict_patterns:
                        pci_conflict_match = re.search(pattern, full_error_text, re.IGNORECASE)
                        if pci_conflict_match:
                            break
                    
                    if pci_conflict_match:
                        pci_device = pci_conflict_match.group(1) if len(pci_conflict_match.groups()) >= 1 else "unknown"
                        conflict_vmid = pci_conflict_match.group(2) if len(pci_conflict_match.groups()) >= 2 else "unknown"
                        
                        def show_pci_conflict() -> None:
                            from main import styled_warning
                            if conflict_vmid != "unknown":
                                styled_warning(
                                    "PCI Device Conflict",
                                    f"Cannot start VM {name} (ID: {vmid}) because PCI device '{pci_device}' is already in use by VM {conflict_vmid}.\n\n"
                                    f"Please stop VM {conflict_vmid} first if you want to use this PCI device on this VM.",
                                    root
                                )
                                status_var.set(f"Cannot start {name} - PCI device '{pci_device}' is in use by VM {conflict_vmid}.")
                            else:
                                styled_warning(
                                    "PCI Device Conflict",
                                    f"Cannot start VM {name} (ID: {vmid}) because PCI device '{pci_device}' is already in use by another VM.\n\n"
                                    f"Please stop the other VM first if you want to use this PCI device on this VM.",
                                    root
                                )
                                status_var.set(f"Cannot start {name} - PCI device '{pci_device}' is in use by another VM.")
                        root.after(0, show_pci_conflict)
                        return
                    # Fallback: check if error mentions PCI device conflict even if regex doesn't match
                    elif "PCI device" in full_error_text.lower() and "already in use" in full_error_text.lower():
                        def show_pci_conflict_generic() -> None:
                            from main import styled_warning
                            styled_warning(
                                "PCI Device Conflict",
                                f"Cannot start VM {name} (ID: {vmid}) because a PCI device is already in use by another VM.\n\n"
                                f"Please stop the other VM first if you want to use this PCI device on this VM.",
                                root
                            )
                            status_var.set(f"Cannot start {name} - PCI device conflict detected.")
                        root.after(0, show_pci_conflict_generic)
                        return
                
                message = f"API error: {exc}"
            except Exception as exc:  # pragma: no cover
                message = f"Unexpected error: {exc}"
            finally:
                if client:
                    client.close()

            # Only finalize if we didn't detect a PCI conflict
            if not pci_conflict_detected:
                def finalize() -> None:
                    status_var.set(message)
                    # Wait a moment for the VM action to complete, then force refresh
                    # Some VMs take longer to start, so we'll do multiple refreshes
                    root.after(1000, lambda: refresh_data(force=True))
                    root.after(3000, lambda: refresh_data(force=True))  # Second refresh after 3 seconds
                    # Also trigger dashboard refresh for consistency
                    refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
                    if callable(refresh_cb):
                        refresh_cb(mode="full", force=True)

                root.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()

    def delete_vm(vm: dict[str, Any]) -> None:
        status = str(vm.get("status", "")).lower()
        name = vm.get("name") or f"VM {vm.get('vmid')}"
        vmid = vm.get("vmid")
        if vmid is None:
            messagebox.showerror("Unknown VM", "Unable to determine the VM ID.", parent=root)
            return

        if status == "running":
            styled_warning(
                "VM is running",
                f"The VM '{name}' is currently running.\n\nPlease stop it before attempting to delete.",
            )
            return

        if not styled_confirm(
            "Delete VM",
            f"Are you sure you want to delete '{name}' (VMID {vmid})?\n\n"
            "This will permanently remove the VM and all associated disks. This action cannot be undone.",
        ):
            return

        account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
        summary = data_holder.get("summary")
        if not account or not summary:
            messagebox.showerror("Unavailable", "Account or VM data is not ready yet.", parent=root)
            return

        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        node_name = getattr(summary, "node_name", None) or vm.get("node")

        if not all([host, username, password, node_name]):
            messagebox.showerror(
                "Missing information",
                "Incomplete connection details or node information.",
                parent=root,
            )
            return

        status_var.set(f"Deleting {name}...")

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
                delete_result = client.delete_vm(node_name, vmid)
                task_id = delete_result.get("upid") if isinstance(delete_result, dict) else None
                message = f"{name} is being deleted."
            except ProxmoxAPIError as exc:
                message = f"Delete failed: {exc}"
            except Exception as exc:  # pragma: no cover
                message = f"Unexpected error: {exc}"
            finally:
                if client:
                    client.close()

            def finalize() -> None:
                status_var.set(message)
                # Some Proxmox deletions are asynchronous; refresh multiple times
                root.after(1500, lambda: refresh_data(force=True))
                root.after(4000, lambda: refresh_data(force=True))
                # Also refresh dashboard
                refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
                if callable(refresh_cb):
                    refresh_cb(mode="full", force=True)

            root.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()

    def render_vm_row(vm: dict[str, Any]) -> None:
        row = tk.Frame(rows_container, bg=PROXMOX_MEDIUM, highlightthickness=1, highlightbackground="#3c434e")
        row.pack(fill=tk.X, pady=6)

        info = tk.Frame(row, bg=PROXMOX_MEDIUM)
        info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=12)

        name = vm.get("name") or f"VM {vm.get('vmid')}"
        tk.Label(
            info,
            text=name,
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(anchor=tk.W)

        tk.Label(
            info,
            text=f"VMID: {vm.get('vmid', 'N/A')}",
            font=("Segoe UI", 11),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(anchor=tk.W, pady=(2, 0))

        status = vm.get("status", "unknown")
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

        action_button("Start", lambda vm=vm: perform_vm_action("start", vm), not running)
        action_button("Stop", lambda vm=vm: perform_vm_action("stop", vm), running)
        action_button("Restart", lambda vm=vm: perform_vm_action("restart", vm), running)
        action_button("Delete", lambda vm=vm: delete_vm(vm), True)

        def open_console(vm_obj: dict[str, Any]) -> None:
            """Launch the VM console in a separate viewer window."""
            account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
            summary_obj = data_holder.get("summary")
            if not account or not summary_obj:
                messagebox.showerror("Unavailable", "Account or VM data is not ready yet.", parent=root)
                return

            vmid = vm_obj.get("vmid")
            if vmid is None:
                messagebox.showerror("Unknown VM", "Unable to determine the VM ID.", parent=root)
                return

            vm_name = vm_obj.get("name") or f"VM {vmid}"
            vm_status = str(vm_obj.get("status", "")).lower()

            if vm_status != "running":
                if not styled_confirm(
                    "Start VM",
                    f"The VM '{vm_name}' is not running. Start it now to open the console?",
                ):
                    return

                status_var.set(f"Starting {vm_name}...")

                def start_vm_worker() -> None:
                    proxmox_cfg = _get_active_proxmox_config(account) or {}
                    host = proxmox_cfg.get("host")
                    username = proxmox_cfg.get("username")
                    password = proxmox_cfg.get("password")
                    verify_ssl = proxmox_cfg.get("verify_ssl", False)
                    trusted_cert = proxmox_cfg.get("trusted_cert")
                    trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
                    node_name = getattr(summary_obj, "node_name", None) or vm_obj.get("node")

                    if not all([host, username, password, node_name]):
                        def show_missing() -> None:
                            messagebox.showerror(
                                "Missing information",
                                "Incomplete connection or node details prevent starting this VM.",
                                parent=root,
                            )
                            status_var.set("Unable to start the VM.")
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
                        
                        # Check for PCI device conflicts before starting
                        try:
                            vm_config = client.get_vm_config(node_name, vmid)
                            all_vms = client.get_node_vms(node_name)
                            pci_conflicts: list[tuple[str, int]] = []
                            
                            for key, value in vm_config.items():
                                if key.startswith("hostpci") and isinstance(value, str):
                                    # Extract PCI ID from value
                                    if "host=" in value:
                                        pci_id = value.split("host=")[1].split(",")[0].strip()
                                    else:
                                        pci_id = value.split(",")[0].strip()
                                    
                                    # Check if this PCI device is used by other running VMs
                                    for vm in all_vms:
                                        other_vmid = vm.get("vmid")
                                        if other_vmid and other_vmid != vmid and vm.get("status") == "running":
                                            try:
                                                other_config = client.get_vm_config(node_name, other_vmid)
                                                for other_key, other_value in other_config.items():
                                                    if other_key.startswith("hostpci") and isinstance(other_value, str):
                                                        if "host=" in other_value:
                                                            other_pci_id = other_value.split("host=")[1].split(",")[0].strip()
                                                        else:
                                                            other_pci_id = other_value.split(",")[0].strip()
                                                        # Check if PCI IDs match (including functions)
                                                        if other_pci_id == pci_id or other_pci_id.startswith(pci_id.split(".")[0] + ".") or pci_id.startswith(other_pci_id.split(".")[0] + "."):
                                                            pci_conflicts.append((pci_id, other_vmid))
                                            except Exception:
                                                pass
                            
                            if pci_conflicts:
                                conflict_messages = []
                                for pci_id, conflict_vmid in pci_conflicts:
                                    conflict_messages.append(f"PCI device {pci_id} is in use by running VM {conflict_vmid}")
                                
                                def show_conflict() -> None:
                                    from main import styled_warning
                                    styled_warning(
                                        "PCI Device Conflict",
                                        "Cannot start VM because the following PCI devices are already in use by other running VMs:\n\n" + "\n".join(conflict_messages) + "\n\nPlease stop the other VMs first or remove the PCI devices from this VM."
                                    )
                                    status_var.set(f"Cannot start {vm_name} - PCI device conflict.")
                                root.after(0, show_conflict)
                                return
                        except Exception:
                            pass  # If conflict check fails, continue with start attempt
                        
                        client.start_vm(node_name, vmid)
                    except ProxmoxAPIError as exc:
                        error_message = str(exc)
                        error_details = getattr(exc, "details", "")
                        
                        # Check if this is a PCI device conflict error
                        # Proxmox error format: "TASK ERROR: PCI device '0000:84:00.0' already in use by VMID '109'"
                        import re
                        full_error_text = str(exc) + " " + str(error_details)
                        # Try multiple patterns to catch different error message formats
                        pci_conflict_patterns = [
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by VMID\s+['\"]?(\d+)['\"]?",
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+already in use by\s+VMID\s+['\"]?(\d+)['\"]?",
                            r"PCI device\s+['\"]?([^'\"]+)['\"]?\s+is already in use by VMID\s+['\"]?(\d+)['\"]?",
                        ]
                        
                        pci_conflict_match = None
                        for pattern in pci_conflict_patterns:
                            pci_conflict_match = re.search(pattern, full_error_text, re.IGNORECASE)
                            if pci_conflict_match:
                                break
                        
                        if pci_conflict_match:
                            pci_device = pci_conflict_match.group(1)
                            conflict_vmid = pci_conflict_match.group(2)
                            
                            def show_pci_conflict() -> None:
                                from main import styled_warning
                                styled_warning(
                                    "PCI Device Conflict",
                                    f"Cannot start VM {vm_name} (ID: {vmid}) because PCI device '{pci_device}' is already in use by VM {conflict_vmid}.\n\n"
                                    f"Please stop VM {conflict_vmid} first if you want to use this PCI device on this VM.",
                                    root
                                )
                                status_var.set(f"Cannot start {vm_name} - PCI device '{pci_device}' is in use by VM {conflict_vmid}.")
                            root.after(0, show_pci_conflict)
                            return
                        
                        # Not a PCI conflict, show generic error
                        error_message = str(exc)
                    except Exception as exc:
                        error_message = str(exc)
                    finally:
                        if client:
                            client.close()

                    def finalize_start() -> None:
                        if error_message:
                            messagebox.showerror("Start VM error", f"Failed to start VM: {error_message}", parent=root)
                            status_var.set(f"Failed to start {vm_name}.")
                        else:
                            status_var.set(f"{vm_name} is starting. Opening console once it is ready...")
                            root.after(
                                4000,
                                lambda: launch_vm_console(
                                    root,
                                    vm_obj,
                                    summary_obj,
                                    status_callback=status_var.set,
                                ),
                            )

                    root.after(0, finalize_start)

                threading.Thread(target=start_vm_worker, daemon=True).start()
                return

            launch_vm_console(root, vm_obj, summary_obj, status_callback=status_var.set)

        def view_vm_details(vm_obj: dict[str, Any]) -> None:
            """Open a detailed VM information window."""
            account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
            summary_obj = data_holder.get("summary")
            if not account or not summary_obj:
                messagebox.showerror("Unavailable", "Account or VM data is not ready yet.", parent=root)
                return
            
            vmid = vm_obj.get("vmid")
            if vmid is None:
                messagebox.showerror("Unknown VM", "Unable to determine the VM ID.", parent=root)
                return
            
            vm_name = vm_obj.get("name") or f"VM {vmid}"
            node_name = getattr(summary_obj, "node_name", None) or vm_obj.get("node")
            
            # Show detailed VM info in current window
            show_vm_details_window(root, account, node_name, vmid, vm_name, vm_obj, rows_container, render_vm_rows)
        
        action_button("Open Console", lambda vm=vm: open_console(vm), True)
        action_button("View Info", lambda vm=vm: view_vm_details(vm), True)
        
        def open_device_management(vm_obj: dict[str, Any]) -> None:
            """Open device management window for a VM."""
            from vm_device_management import show_device_management
            account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
            summary_obj = data_holder.get("summary")
            if not account or not summary_obj:
                messagebox.showerror("Unavailable", "Account or VM data is not ready yet.", parent=root)
                return
            
            vmid = vm_obj.get("vmid")
            if vmid is None:
                messagebox.showerror("Unknown VM", "Unable to determine the VM ID.", parent=root)
                return
            
            vm_name = vm_obj.get("name") or f"VM {vmid}"
            node_name = getattr(summary_obj, "node_name", None) or vm_obj.get("node")
            
            if not node_name:
                messagebox.showerror("Unknown Node", "Unable to determine the node name.", parent=root)
                return
            
            show_device_management(root, account, node_name, vmid, vm_name, rows_container, render_vm_rows)
        
        action_button("Device Management", lambda vm=vm: open_device_management(vm), True)

    def refresh_data(force: bool = False) -> None:
        app_state = getattr(root, "app_state", None)
        account = app_state.get("account") if isinstance(app_state, dict) else None
        
        if force and account:
            # Force refresh: fetch data directly from Proxmox
            status_var.set("Requesting latest VM data...")
            
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
                        vms = getattr(summary, "vms", None)
                        if vms is None and isinstance(summary, dict):
                            vms = summary.get("vms")
                        
                        data_holder["summary"] = summary
                        data_holder["vms"] = list(vms or [])
                        status_var.set(f"{len(data_holder['vms'])} virtual machines loaded.")
                        render_vm_rows()
                        
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
            status_var.set("No VM data available. Use Refresh to load from Proxmox.")
            data_holder["summary"] = None
            data_holder["vms"] = []
            render_vm_rows()
            return

        vms = getattr(summary, "vms", None)
        if vms is None and isinstance(summary, dict):
            vms = summary.get("vms")

        data_holder["summary"] = summary
        data_holder["vms"] = list(vms or [])
        status_var.set(f"{len(data_holder['vms'])} virtual machines loaded.")
        render_vm_rows()
        dock_refresh = getattr(root, "refresh_dock_panel", None)
        if callable(dock_refresh):
            root.after_idle(dock_refresh)

    search_var.trace_add("write", lambda *_: render_vm_rows())
    refresh_data()
    search_entry.focus_set()

    return frame

