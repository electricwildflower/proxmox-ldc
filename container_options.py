from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

from proxmox_client import ProxmoxAPIError, ProxmoxClient
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE


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


def show_container_options(
    parent: tk.Tk,
    account: dict,
    node_name: str,
    vmid: int,
    container_name: str,
    rows_container: tk.Frame,
    render_container_rows_func,
) -> None:
    """Show container options in the main window."""
    # Clear the rows container
    for child in rows_container.winfo_children():
        child.destroy()
    
    # Create a container for the options view
    options_container = tk.Frame(rows_container, bg=PROXMOX_DARK)
    options_container.pack(fill=tk.BOTH, expand=True)
    
    # Header with back button
    header = tk.Frame(options_container, bg=PROXMOX_DARK)
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
        text=f"Container Options - {container_name}",
        font=("Segoe UI", 20, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(20, 0))
    
    # Main content with scrollable canvas (no scrollbar)
    canvas = tk.Canvas(options_container, bg=PROXMOX_DARK, highlightthickness=0)
    scrollable_frame = tk.Frame(canvas, bg=PROXMOX_DARK)
    
    def update_scrollregion(event: tk.Event = None) -> None:
        canvas.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
    
    scrollable_frame.bind("<Configure>", update_scrollregion)
    canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    
    def configure_canvas(event: tk.Event) -> None:
        canvas_width = event.width
        canvas.itemconfig(canvas_window, width=canvas_width)
        update_scrollregion()
    
    canvas.bind("<Configure>", configure_canvas)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    # Make canvas focusable for scrolling
    canvas.focus_set()
    canvas.bind("<Enter>", lambda e: canvas.focus_set())
    canvas.bind("<Leave>", lambda e: canvas.focus_set())
    
    # Mouse wheel scrolling
    def on_mousewheel(event: tk.Event) -> None:
        if event.delta:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"
    
    def on_mousewheel_linux_up(event: tk.Event) -> None:
        canvas.yview_scroll(-3, "units")
        return "break"
    
    def on_mousewheel_linux_down(event: tk.Event) -> None:
        canvas.yview_scroll(3, "units")
        return "break"
    
    def bind_mousewheel_to_widget(widget: tk.Widget) -> None:
        widget.bind("<MouseWheel>", on_mousewheel)
        widget.bind("<Button-4>", on_mousewheel_linux_up)
        widget.bind("<Button-5>", on_mousewheel_linux_down)
        for child in widget.winfo_children():
            bind_mousewheel_to_widget(child)
    
    bind_mousewheel_to_widget(canvas)
    bind_mousewheel_to_widget(scrollable_frame)
    bind_mousewheel_to_widget(options_container)
    
    content = tk.Frame(scrollable_frame, bg=PROXMOX_DARK)
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    
    # Loading indicator
    loading_label = tk.Label(
        content,
        text="Loading container options...",
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    loading_label.pack(pady=20)
    
    # Options frame
    options_frame = tk.Frame(content, bg=PROXMOX_DARK)
    
    # Store container config and variables
    container_config: dict[str, Any] = {}
    proxmox_cfg: dict[str, Any] = {}
    
    # Option variables
    onboot_var = tk.BooleanVar()
    startup_order_var = tk.StringVar()
    startup_delay_var = tk.StringVar()
    shutdown_order_var = tk.StringVar()
    shutdown_timeout_var = tk.StringVar()
    protection_var = tk.BooleanVar()
    unprivileged_var = tk.BooleanVar()
    nesting_var = tk.BooleanVar()
    keyctl_var = tk.BooleanVar()
    fuse_var = tk.BooleanVar()
    mknod_var = tk.BooleanVar()
    mount_var = tk.StringVar()  # comma-separated
    rootfs_var = tk.StringVar()
    swap_var = tk.StringVar()
    memory_var = tk.StringVar()
    cores_var = tk.StringVar()
    cpuunits_var = tk.StringVar()
    cpulimit_var = tk.StringVar()
    net0_var = tk.StringVar()
    hostname_var = tk.StringVar()
    nameserver_var = tk.StringVar()
    searchdomain_var = tk.StringVar()
    ostype_var = tk.StringVar()
    arch_var = tk.StringVar()
    
    def load_container_options() -> None:
        """Load container configuration options."""
        nonlocal container_config, proxmox_cfg
        
        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        
        if not all([host, username, password, node_name]):
            loading_label.config(text="Unable to load options: missing credentials")
            return
        
        def worker() -> None:
            nonlocal container_config
            client: ProxmoxClient | None = None
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
                        scrollable_frame,
                        text=f"Error loading options: {error_msg}",
                        font=("Segoe UI", 11),
                        fg="#f44336",
                        bg=PROXMOX_DARK,
                    ).pack(pady=20)
                    return
                
                # Populate option variables from config
                onboot_var.set(container_config.get("onboot", 0) == 1)
                
                startup = container_config.get("startup", "")
                if startup:
                    parts = startup.split(",")
                    for part in parts:
                        part = part.strip()
                        if "order=" in part:
                            startup_order_var.set(part.split("order=")[1].strip())
                        elif "up=" in part:
                            startup_delay_var.set(part.split("up=")[1].strip())
                        elif "down=" in part:
                            shutdown_order_var.set(part.split("down=")[1].strip())
                
                shutdown = container_config.get("shutdown", "")
                if shutdown:
                    if "timeout=" in shutdown:
                        shutdown_timeout_var.set(shutdown.split("timeout=")[1].strip())
                
                protection_var.set(container_config.get("protection", 0) == 1)
                unprivileged_var.set(container_config.get("unprivileged", 0) == 1)
                
                # Features
                features = container_config.get("features", "")
                if features:
                    features_str = str(features)
                    nesting_var.set("nesting=1" in features_str or "nesting" in features_str)
                    keyctl_var.set("keyctl=1" in features_str or "keyctl" in features_str)
                    fuse_var.set("fuse=1" in features_str or "fuse" in features_str)
                    mknod_var.set("mknod=1" in features_str or "mknod" in features_str)
                    mount_val = []
                    if "mount=" in features_str:
                        mount_parts = features_str.split("mount=")[1].split(",")[0].strip()
                        mount_val.append(mount_parts)
                    if mount_val:
                        mount_var.set(",".join(mount_val))
                
                rootfs_var.set(container_config.get("rootfs", ""))
                swap_var.set(str(container_config.get("swap", "")))
                memory_var.set(str(container_config.get("memory", "")))
                cores_var.set(str(container_config.get("cores", "")))
                cpuunits_var.set(str(container_config.get("cpuunits", "")))
                cpulimit_var.set(str(container_config.get("cpulimit", "")))
                net0_var.set(container_config.get("net0", ""))
                hostname_var.set(container_config.get("hostname", ""))
                nameserver_var.set(container_config.get("nameserver", ""))
                searchdomain_var.set(container_config.get("searchdomain", ""))
                ostype_var.set(container_config.get("ostype", ""))
                arch_var.set(container_config.get("arch", ""))
                
                render_options()
                options_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                # Bind mouse wheel to newly created widgets
                bind_mousewheel_to_widget(content)
                bind_mousewheel_to_widget(options_frame)
                update_scrollregion()
            
            parent.after(0, update_ui)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def create_option_row(
        parent: tk.Frame,
        label: str,
        widget: tk.Widget,
        description: str = "",
    ) -> None:
        """Create a row for an option with label and widget."""
        row = tk.Frame(parent, bg=PROXMOX_DARK)
        row.pack(fill=tk.X, pady=10, padx=10)
        
        # Left side: Label and description
        left_frame = tk.Frame(row, bg=PROXMOX_DARK)
        left_frame.pack(side=tk.LEFT, padx=(0, 20), anchor=tk.N)
        
        tk.Label(
            left_frame,
            text=label,
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            width=22,
            anchor="w",
        ).pack(anchor=tk.W)
        
        if description:
            tk.Label(
                left_frame,
                text=description,
                font=("Segoe UI", 9),
                fg=PROXMOX_MEDIUM,
                bg=PROXMOX_DARK,
                wraplength=250,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, pady=(4, 0))
        
        # Right side: Widget
        right_frame = tk.Frame(row, bg=PROXMOX_DARK)
        right_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # For checkboxes, don't expand
        if isinstance(widget, tk.Checkbutton):
            widget.pack(anchor=tk.W)
        else:
            widget.pack(fill=tk.X, expand=True)
    
    def render_options() -> None:
        """Render all option controls."""
        # Clear existing content
        for widget in options_frame.winfo_children():
            widget.destroy()
        
        # Section: General Options
        section1 = tk.LabelFrame(
            options_frame,
            text="General Options",
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
            bd=2,
            relief=tk.SOLID,
            labelanchor="nw",
        )
        section1.pack(fill=tk.X, pady=(0, 20), padx=10)
        section1_content = tk.Frame(section1, bg=PROXMOX_DARK)
        section1_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Start at boot
        onboot_cb = tk.Checkbutton(
            section1_content,
            text="Start at boot",
            variable=onboot_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section1_content,
            "Start at boot",
            onboot_cb,
            "Automatically start container when the host boots",
        )
        
        # Startup/Shutdown order
        startup_container = tk.Frame(section1_content, bg=PROXMOX_DARK)
        startup_container.pack(fill=tk.X, pady=10, padx=10)
        
        startup_label_frame = tk.Frame(startup_container, bg=PROXMOX_DARK)
        startup_label_frame.pack(side=tk.LEFT, padx=(0, 20), anchor=tk.N)
        
        tk.Label(
            startup_label_frame,
            text="Startup/Shutdown Order:",
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            width=22,
            anchor="w",
        ).pack(anchor=tk.W)
        
        tk.Label(
            startup_label_frame,
            text="Configure startup and shutdown order and delays",
            font=("Segoe UI", 9),
            fg=PROXMOX_MEDIUM,
            bg=PROXMOX_DARK,
            wraplength=250,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 0))
        
        startup_input_frame = tk.Frame(startup_container, bg=PROXMOX_DARK)
        startup_input_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        fields_frame = tk.Frame(startup_input_frame, bg=PROXMOX_DARK)
        fields_frame.pack(fill=tk.X)
        
        tk.Label(
            fields_frame,
            text="Order:",
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        startup_order_entry = tk.Entry(
            fields_frame,
            textvariable=startup_order_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=8,
        )
        startup_order_entry.pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Label(
            fields_frame,
            text="Startup Delay:",
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        startup_delay_entry = tk.Entry(
            fields_frame,
            textvariable=startup_delay_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=8,
        )
        startup_delay_entry.pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Label(
            fields_frame,
            text="Shutdown Delay:",
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        shutdown_delay_entry = tk.Entry(
            fields_frame,
            textvariable=shutdown_order_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=8,
        )
        shutdown_delay_entry.pack(side=tk.LEFT)
        
        tk.Label(
            startup_input_frame,
            text="Format: order=1,up=30,down=30 (order: boot order, up: startup delay in seconds, down: shutdown delay in seconds)",
            font=("Segoe UI", 9),
            fg=PROXMOX_MEDIUM,
            bg=PROXMOX_DARK,
            wraplength=500,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(8, 0))
        
        # Protection
        protection_cb = tk.Checkbutton(
            section1_content,
            text="Protection",
            variable=protection_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section1_content,
            "Protection",
            protection_cb,
            "Prevent container from being deleted or stopped",
        )
        
        # OS Type
        ostype_entry = tk.Entry(
            section1_content,
            textvariable=ostype_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section1_content,
            "OS Type",
            ostype_entry,
            "Container OS type (e.g., debian, ubuntu, alpine)",
        )
        
        # Architecture
        arch_entry = tk.Entry(
            section1_content,
            textvariable=arch_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section1_content,
            "Architecture",
            arch_entry,
            "Container architecture (amd64, arm64, etc.)",
        )
        
        # Section: Security Options
        section2 = tk.LabelFrame(
            options_frame,
            text="Security Options",
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
            bd=2,
            relief=tk.SOLID,
            labelanchor="nw",
        )
        section2.pack(fill=tk.X, pady=(0, 20), padx=10)
        section2_content = tk.Frame(section2, bg=PROXMOX_DARK)
        section2_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Unprivileged
        unprivileged_cb = tk.Checkbutton(
            section2_content,
            text="Unprivileged",
            variable=unprivileged_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Unprivileged",
            unprivileged_cb,
            "Run container in unprivileged mode (more secure)",
        )
        
        # Features
        nesting_cb = tk.Checkbutton(
            section2_content,
            text="Nesting",
            variable=nesting_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Nesting",
            nesting_cb,
            "Enable container nesting (run containers inside containers)",
        )
        
        keyctl_cb = tk.Checkbutton(
            section2_content,
            text="Keyctl",
            variable=keyctl_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Keyctl",
            keyctl_cb,
            "Enable keyctl support",
        )
        
        fuse_cb = tk.Checkbutton(
            section2_content,
            text="FUSE",
            variable=fuse_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "FUSE",
            fuse_cb,
            "Enable FUSE filesystem support",
        )
        
        mknod_cb = tk.Checkbutton(
            section2_content,
            text="Mknod",
            variable=mknod_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Mknod",
            mknod_cb,
            "Enable mknod support",
        )
        
        mount_entry = tk.Entry(
            section2_content,
            textvariable=mount_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "Mount",
            mount_entry,
            "Mount options (comma-separated, e.g., nfs, cifs)",
        )
        
        # Section: Resource Limits
        section3 = tk.LabelFrame(
            options_frame,
            text="Resource Limits",
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
            bd=2,
            relief=tk.SOLID,
            labelanchor="nw",
        )
        section3.pack(fill=tk.X, pady=(0, 20), padx=10)
        section3_content = tk.Frame(section3, bg=PROXMOX_DARK)
        section3_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Memory
        memory_entry = tk.Entry(
            section3_content,
            textvariable=memory_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section3_content,
            "Memory",
            memory_entry,
            "Memory limit in MB (e.g., 512)",
        )
        
        # Swap
        swap_entry = tk.Entry(
            section3_content,
            textvariable=swap_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section3_content,
            "Swap",
            swap_entry,
            "Swap space in MB (e.g., 512)",
        )
        
        # CPU Cores
        cores_entry = tk.Entry(
            section3_content,
            textvariable=cores_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section3_content,
            "CPU Cores",
            cores_entry,
            "Number of CPU cores (e.g., 2)",
        )
        
        # CPU Units
        cpuunits_entry = tk.Entry(
            section3_content,
            textvariable=cpuunits_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section3_content,
            "CPU Units",
            cpuunits_entry,
            "CPU weight (e.g., 1024)",
        )
        
        # CPU Limit
        cpulimit_entry = tk.Entry(
            section3_content,
            textvariable=cpulimit_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section3_content,
            "CPU Limit",
            cpulimit_entry,
            "CPU limit in percent (e.g., 50)",
        )
        
        # Section: Network & Storage
        section4 = tk.LabelFrame(
            options_frame,
            text="Network & Storage",
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
            bd=2,
            relief=tk.SOLID,
            labelanchor="nw",
        )
        section4.pack(fill=tk.X, pady=(0, 20), padx=10)
        section4_content = tk.Frame(section4, bg=PROXMOX_DARK)
        section4_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Root Filesystem
        rootfs_entry = tk.Entry(
            section4_content,
            textvariable=rootfs_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section4_content,
            "Root Filesystem",
            rootfs_entry,
            "Root filesystem storage and size (e.g., local-lvm:8)",
        )
        
        # Network
        net0_entry = tk.Entry(
            section4_content,
            textvariable=net0_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section4_content,
            "Network",
            net0_entry,
            "Network configuration (e.g., name=eth0,bridge=vmbr0,ip=dhcp)",
        )
        
        # Hostname
        hostname_entry = tk.Entry(
            section4_content,
            textvariable=hostname_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section4_content,
            "Hostname",
            hostname_entry,
            "Container hostname",
        )
        
        # Nameserver
        nameserver_entry = tk.Entry(
            section4_content,
            textvariable=nameserver_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section4_content,
            "Nameserver",
            nameserver_entry,
            "DNS nameserver (e.g., 8.8.8.8 or 8.8.8.8 8.8.4.4)",
        )
        
        # Search Domain
        searchdomain_entry = tk.Entry(
            section4_content,
            textvariable=searchdomain_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section4_content,
            "Search Domain",
            searchdomain_entry,
            "DNS search domain",
        )
        
        update_scrollregion()
    
    def save_options() -> None:
        """Save container options."""
        def check_and_save() -> None:
            client: ProxmoxClient | None = None
            try:
                client = ProxmoxClient(
                    host=proxmox_cfg.get("host"),
                    username=proxmox_cfg.get("username"),
                    password=proxmox_cfg.get("password"),
                    verify_ssl=proxmox_cfg.get("verify_ssl", False),
                    trusted_cert=proxmox_cfg.get("trusted_cert"),
                    trusted_fingerprint=proxmox_cfg.get("trusted_cert_fingerprint"),
                )
                
                # Check container status
                containers = client.get_node_containers(node_name)
                container_runtime = next((ct for ct in containers if ct.get("vmid") == vmid), None)
                if container_runtime and container_runtime.get("status") == "running":
                    def show_warning() -> None:
                        from main import styled_warning
                        styled_warning(
                            "Container Running",
                            "Some options may require the container to be stopped to take effect. Please stop the container if needed.",
                            parent
                        )
                    parent.after(0, show_warning)
                
                # Build new config
                new_config: dict[str, Any] = {}
                
                # Start at boot
                new_config["onboot"] = 1 if onboot_var.get() else 0
                
                # Startup/Shutdown order
                startup_parts = []
                if startup_order_var.get():
                    startup_parts.append(f"order={startup_order_var.get()}")
                if startup_delay_var.get():
                    startup_parts.append(f"up={startup_delay_var.get()}")
                if shutdown_order_var.get():
                    startup_parts.append(f"down={shutdown_order_var.get()}")
                if startup_parts:
                    new_config["startup"] = ",".join(startup_parts)
                
                if shutdown_timeout_var.get():
                    new_config["shutdown"] = f"timeout={shutdown_timeout_var.get()}"
                
                # Protection
                new_config["protection"] = 1 if protection_var.get() else 0
                
                # Unprivileged
                new_config["unprivileged"] = 1 if unprivileged_var.get() else 0
                
                # Features
                feature_parts = []
                if nesting_var.get():
                    feature_parts.append("nesting=1")
                if keyctl_var.get():
                    feature_parts.append("keyctl=1")
                if fuse_var.get():
                    feature_parts.append("fuse=1")
                if mknod_var.get():
                    feature_parts.append("mknod=1")
                if mount_var.get():
                    feature_parts.append(f"mount={mount_var.get()}")
                if feature_parts:
                    new_config["features"] = ",".join(feature_parts)
                
                # Resource limits
                if memory_var.get() and memory_var.get().strip():
                    try:
                        new_config["memory"] = int(memory_var.get().strip())
                    except ValueError:
                        pass
                if swap_var.get() and swap_var.get().strip():
                    try:
                        new_config["swap"] = int(swap_var.get().strip())
                    except ValueError:
                        pass
                if cores_var.get() and cores_var.get().strip():
                    try:
                        new_config["cores"] = int(cores_var.get().strip())
                    except ValueError:
                        pass
                if cpuunits_var.get() and cpuunits_var.get().strip():
                    try:
                        new_config["cpuunits"] = int(cpuunits_var.get().strip())
                    except ValueError:
                        pass
                if cpulimit_var.get() and cpulimit_var.get().strip():
                    try:
                        new_config["cpulimit"] = float(cpulimit_var.get().strip())
                    except ValueError:
                        pass
                
                # Network & Storage
                if rootfs_var.get():
                    new_config["rootfs"] = rootfs_var.get()
                if net0_var.get():
                    new_config["net0"] = net0_var.get()
                if hostname_var.get():
                    new_config["hostname"] = hostname_var.get()
                if nameserver_var.get():
                    new_config["nameserver"] = nameserver_var.get()
                if searchdomain_var.get():
                    new_config["searchdomain"] = searchdomain_var.get()
                
                # OS Type and Architecture
                if ostype_var.get():
                    new_config["ostype"] = ostype_var.get()
                if arch_var.get():
                    new_config["arch"] = arch_var.get()
                
                # Apply changes
                client.update_container_config(node_name, vmid, new_config)
                
                def show_success() -> None:
                    from main import styled_info
                    styled_info("Options Saved", "Container options have been updated successfully.", parent)
                    go_back()
                parent.after(0, show_success)
                
            except ProxmoxAPIError as exc:
                def show_error() -> None:
                    from main import styled_error
                    styled_error("Save Failed", f"Failed to save container options:\n{exc}", parent)
                parent.after(0, show_error)
            except Exception as exc:
                def show_error() -> None:
                    from main import styled_error
                    styled_error("Save Failed", f"Error: {exc}", parent)
                parent.after(0, show_error)
            finally:
                if client:
                    client.close()
        
        threading.Thread(target=check_and_save, daemon=True).start()
    
    # Footer with save button
    footer = tk.Frame(options_container, bg=PROXMOX_DARK)
    footer.pack(fill=tk.X, padx=20, pady=(0, 20))
    
    tk.Button(
        footer,
        text="Save Options",
        command=save_options,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.RIGHT)
    
    # Load container options
    parent.after(100, load_container_options)

