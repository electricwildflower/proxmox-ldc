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


def show_vm_options(
    parent: tk.Tk,
    account: dict,
    node_name: str,
    vmid: int,
    vm_name: str,
    rows_container: tk.Frame,
    render_vm_rows_func,
) -> None:
    """Show VM options in the main window."""
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
        text=f"VM Options - {vm_name}",
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
    
    # Bind mouse wheel to canvas and all child widgets
    bind_mousewheel_to_widget(canvas)
    bind_mousewheel_to_widget(scrollable_frame)
    bind_mousewheel_to_widget(options_container)
    
    content = tk.Frame(scrollable_frame, bg=PROXMOX_DARK)
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    
    # Loading indicator
    loading_label = tk.Label(
        content,
        text="Loading VM options...",
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    loading_label.pack(pady=20)
    
    # Options frame (will be packed when options are loaded)
    options_frame = tk.Frame(content, bg=PROXMOX_DARK)
    
    # Store VM config and variables
    vm_config: dict[str, Any] = {}
    proxmox_cfg: dict[str, Any] = {}
    boot_listbox_ref: tk.Listbox | None = None  # Reference to boot order listbox
    
    # Option variables
    onboot_var = tk.BooleanVar()
    startup_order_var = tk.StringVar()
    startup_delay_var = tk.StringVar()
    shutdown_order_var = tk.StringVar()
    shutdown_timeout_var = tk.StringVar()
    ostype_var = tk.StringVar()
    boot_order_list: list[str] = []  # List of boot devices for drag-and-drop
    tablet_var = tk.BooleanVar()
    hotplug_var = tk.StringVar()  # comma-separated list
    acpi_var = tk.BooleanVar()
    kvm_var = tk.BooleanVar()
    freeze_var = tk.BooleanVar()
    localtime_var = tk.BooleanVar()
    rtc_startdate_var = tk.StringVar()
    smbios1_var = tk.StringVar()
    agent_enabled_var = tk.BooleanVar()  # Agent enabled/disabled
    protection_var = tk.BooleanVar()
    spice_enhancements_var = tk.StringVar()  # comma-separated
    vmstate_var = tk.StringVar()
    sev_var = tk.StringVar()  # AMD SEV options
    
    def load_vm_options() -> None:
        """Load VM configuration options."""
        nonlocal vm_config, proxmox_cfg
        
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
            nonlocal vm_config
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
                        scrollable_frame,
                        text=f"Error loading options: {error_msg}",
                        font=("Segoe UI", 11),
                        fg="#f44336",
                        bg=PROXMOX_DARK,
                    ).pack(pady=20)
                    return
                
                # Populate option variables from config
                onboot_var.set(vm_config.get("onboot", 0) == 1)
                
                startup = vm_config.get("startup", "")
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
                
                shutdown = vm_config.get("shutdown", "")
                if shutdown:
                    if "timeout=" in shutdown:
                        shutdown_timeout_var.set(shutdown.split("timeout=")[1].strip())
                
                ostype_var.set(vm_config.get("ostype", "l26"))
                
                boot = vm_config.get("boot", "")
                if boot and "order=" in boot:
                    boot_order_str = boot.split("order=")[1].strip()
                    boot_order_list.clear()
                    boot_order_list.extend([d.strip() for d in boot_order_str.split(";") if d.strip()])
                else:
                    boot_order_list.clear()
                
                tablet_var.set(vm_config.get("tablet", 0) == 1)
                
                hotplug_val = vm_config.get("hotplug", "")
                if hotplug_val:
                    hotplug_var.set(hotplug_val)
                
                acpi_var.set(vm_config.get("acpi", 1) == 1)
                kvm_var.set(vm_config.get("kvm", 1) == 1)
                freeze_var.set(vm_config.get("freeze", 0) == 1)
                localtime_var.set(vm_config.get("localtime", 0) == 1)
                
                rtc_startdate_var.set(vm_config.get("rtcstartdate", ""))
                
                smbios1_var.set(vm_config.get("smbios1", ""))
                
                agent = vm_config.get("agent", "")
                if agent and "enabled=1" in str(agent):
                    agent_enabled_var.set(True)
                else:
                    agent_enabled_var.set(False)
                
                protection_var.set(vm_config.get("protection", 0) == 1)
                
                spice_enhancements = []
                if vm_config.get("spice_enhancements"):
                    spice_enhancements_var.set(vm_config.get("spice_enhancements", ""))
                
                vmstate_var.set(vm_config.get("vmstate", ""))
                
                sev = vm_config.get("sev", "")
                if sev:
                    sev_var.set(sev)
                
                options_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                render_options()
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
        
        # A - Start at boot
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
            "Automatically start VM when the host boots",
        )
        
        # B - Start/Shutdown order
        startup_container = tk.Frame(section1_content, bg=PROXMOX_DARK)
        startup_container.pack(fill=tk.X, pady=10, padx=10)
        
        # Label and description
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
        
        # Input fields
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
        
        # C - OS Type
        ostype_combo = ttk.Combobox(
            section1_content,
            textvariable=ostype_var,
            values=["l26", "wxp", "w2k", "w2k3", "w2k8", "wvista", "win7", "win8", "win10", "win11", "other"],
            state="readonly",
            width=20,
        )
        create_option_row(
            section1_content,
            "OS Type",
            ostype_combo,
            "Guest operating system type",
        )
        
        # D - Boot Order (Drag and Drop)
        boot_order_container = tk.Frame(section1_content, bg=PROXMOX_DARK)
        boot_order_container.pack(fill=tk.X, pady=10, padx=10)
        
        # Label and description
        boot_label_frame = tk.Frame(boot_order_container, bg=PROXMOX_DARK)
        boot_label_frame.pack(side=tk.LEFT, padx=(0, 20), anchor=tk.N)
        
        tk.Label(
            boot_label_frame,
            text="Boot Order:",
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            width=22,
            anchor="w",
        ).pack(anchor=tk.W)
        
        tk.Label(
            boot_label_frame,
            text="Drag and drop devices to reorder boot sequence",
            font=("Segoe UI", 9),
            fg=PROXMOX_MEDIUM,
            bg=PROXMOX_DARK,
            wraplength=250,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 0))
        
        # Boot order list frame
        boot_list_frame = tk.Frame(boot_order_container, bg=PROXMOX_DARK)
        boot_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Listbox with scrollbar for boot order
        boot_listbox_frame = tk.Frame(boot_list_frame, bg=PROXMOX_DARK)
        boot_listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        boot_listbox = tk.Listbox(
            boot_listbox_frame,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            selectbackground=PROXMOX_ORANGE,
            selectforeground="white",
            activestyle="none",
            height=6,
        )
        boot_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Populate listbox
        for device in boot_order_list:
            boot_listbox.insert(tk.END, device)
        
        # Drag and drop functionality
        drag_start_index: int | None = None
        is_dragging = False
        
        def on_click(event: tk.Event) -> None:
            """Handle initial click - select item."""
            nonlocal drag_start_index, is_dragging
            index = boot_listbox.nearest(event.y)
            if index >= 0:
                boot_listbox.selection_clear(0, tk.END)
                boot_listbox.selection_set(index)
                boot_listbox.see(index)
                drag_start_index = index
                is_dragging = False
        
        def on_drag_motion(event: tk.Event) -> None:
            """Handle drag motion - show where item will be dropped."""
            nonlocal drag_start_index, is_dragging
            if drag_start_index is not None:
                is_dragging = True
                boot_listbox.config(cursor="hand2")
                # Find which item we're over
                index = boot_listbox.nearest(event.y)
                if index != drag_start_index and index >= 0:
                    # Highlight the potential drop position
                    boot_listbox.selection_clear(0, tk.END)
                    boot_listbox.selection_set(index)
                    boot_listbox.see(index)
        
        def on_release(event: tk.Event) -> None:
            """Handle mouse release - perform the move."""
            nonlocal drag_start_index, is_dragging
            if drag_start_index is not None and is_dragging:
                # Find drop target
                drop_index = boot_listbox.nearest(event.y)
                if drop_index != drag_start_index and drop_index >= 0:
                    # Get the item being moved
                    item = boot_listbox.get(drag_start_index)
                    # Remove from old position
                    boot_listbox.delete(drag_start_index)
                    # Adjust drop index if item was removed before it
                    if drop_index > drag_start_index:
                        drop_index -= 1
                    # Insert at new position
                    boot_listbox.insert(drop_index, item)
                    # Update the list
                    boot_order_list.clear()
                    boot_order_list.extend(boot_listbox.get(0, tk.END))
                    # Select the moved item
                    boot_listbox.selection_clear(0, tk.END)
                    boot_listbox.selection_set(drop_index)
                    boot_listbox.see(drop_index)
            
            drag_start_index = None
            is_dragging = False
            boot_listbox.config(cursor="arrow")
        
        # Bind drag and drop events
        boot_listbox.bind("<Button-1>", on_click)
        boot_listbox.bind("<B1-Motion>", on_drag_motion)
        boot_listbox.bind("<ButtonRelease-1>", on_release)
        
        # Store reference to listbox for save function
        nonlocal boot_listbox_ref
        boot_listbox_ref = boot_listbox
        
        # Section: Hardware Options
        section2 = tk.LabelFrame(
            options_frame,
            text="Hardware Options",
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
        
        # E - Tablet
        tablet_cb = tk.Checkbutton(
            section2_content,
            text="Use tablet for pointer",
            variable=tablet_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Tablet",
            tablet_cb,
            "Enable tablet pointer device",
        )
        
        # F - Hotplug
        hotplug_entry = tk.Entry(
            section2_content,
            textvariable=hotplug_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "Hotplug",
            hotplug_entry,
            "Comma-separated list of hotplug devices (e.g., disk,network,usb)",
        )
        
        # G - ACPI
        acpi_cb = tk.Checkbutton(
            section2_content,
            text="ACPI support",
            variable=acpi_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "ACPI",
            acpi_cb,
            "Enable ACPI support",
        )
        
        # H - KVM
        kvm_cb = tk.Checkbutton(
            section2_content,
            text="KVM hardware virtualization",
            variable=kvm_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "KVM",
            kvm_cb,
            "Enable KVM hardware virtualization",
        )
        
        # I - Freeze
        freeze_cb = tk.Checkbutton(
            section2_content,
            text="Freeze CPU at startup",
            variable=freeze_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Freeze CPU",
            freeze_cb,
            "Freeze CPU at startup (for debugging)",
        )
        
        # J - Local time
        localtime_cb = tk.Checkbutton(
            section2_content,
            text="Use local time for RTC",
            variable=localtime_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "Local Time RTC",
            localtime_cb,
            "Use local time instead of UTC for RTC",
        )
        
        # K - RTC Start Date
        rtc_startdate_entry = tk.Entry(
            section2_content,
            textvariable=rtc_startdate_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "RTC Start Date",
            rtc_startdate_entry,
            "RTC start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)",
        )
        
        # L - SMBIOS
        smbios1_entry = tk.Entry(
            section2_content,
            textvariable=smbios1_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "SMBIOS Settings",
            smbios1_entry,
            "SMBIOS type 1 fields (e.g., uuid=...,manufacturer=...,product=...)",
        )
        
        # M - QEMU Guest Agent
        agent_cb = tk.Checkbutton(
            section2_content,
            text="QEMU Guest Agent",
            variable=agent_enabled_var,
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            selectcolor=PROXMOX_DARK,
            activebackground=PROXMOX_DARK,
            activeforeground=PROXMOX_LIGHT,
        )
        create_option_row(
            section2_content,
            "QEMU Guest Agent",
            agent_cb,
            "Enable QEMU Guest Agent for better VM management",
        )
        
        # N - Protection
        protection_cb = tk.Checkbutton(
            section2_content,
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
            section2_content,
            "Protection",
            protection_cb,
            "Prevent VM from being deleted or stopped",
        )
        
        # O - Spice Enhancements
        spice_enhancements_entry = tk.Entry(
            section2_content,
            textvariable=spice_enhancements_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "Spice Enhancements",
            spice_enhancements_entry,
            "Comma-separated list (e.g., foldersharing=1,clipboard=1)",
        )
        
        # P - VM State Storage
        vmstate_entry = tk.Entry(
            section2_content,
            textvariable=vmstate_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "VM State Storage",
            vmstate_entry,
            "Storage for VM state (leave empty for default)",
        )
        
        # Q - AMD SEV
        sev_entry = tk.Entry(
            section2_content,
            textvariable=sev_var,
            font=("Segoe UI", 10),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            width=40,
        )
        create_option_row(
            section2_content,
            "AMD SEV",
            sev_entry,
            "AMD SEV options (e.g., cbitpos=47,reducedphysaddr=1)",
        )
        
        update_scrollregion()
    
    def save_options() -> None:
        """Save VM options."""
        def check_and_save() -> None:
            nonlocal boot_listbox_ref
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
                
                # Check VM status
                vms = client.get_node_vms(node_name)
                vm_runtime = next((vm for vm in vms if vm.get("vmid") == vmid), None)
                if vm_runtime and vm_runtime.get("status") == "running":
                    def show_warning() -> None:
                        from main import styled_warning
                        styled_warning(
                            "VM Running",
                            "Some options may require the VM to be stopped to take effect. Please stop the VM if needed.",
                            parent
                        )
                    parent.after(0, show_warning)
                
                # Build new config
                new_config: dict[str, Any] = {}
                
                # A - Start at boot
                new_config["onboot"] = 1 if onboot_var.get() else 0
                
                # B - Startup/Shutdown order
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
                
                # C - OS Type
                if ostype_var.get():
                    new_config["ostype"] = ostype_var.get()
                
                # D - Boot Order
                # Get current boot order from listbox
                if boot_listbox_ref:
                    boot_order_list.clear()
                    boot_order_list.extend(boot_listbox_ref.get(0, tk.END))
                
                if boot_order_list:
                    boot_order = ";".join(boot_order_list)
                    new_config["boot"] = f"order={boot_order}"
                
                # E - Tablet
                new_config["tablet"] = 1 if tablet_var.get() else 0
                
                # F - Hotplug
                if hotplug_var.get():
                    new_config["hotplug"] = hotplug_var.get()
                
                # G - ACPI
                new_config["acpi"] = 1 if acpi_var.get() else 0
                
                # H - KVM
                new_config["kvm"] = 1 if kvm_var.get() else 0
                
                # I - Freeze
                new_config["freeze"] = 1 if freeze_var.get() else 0
                
                # J - Local time
                new_config["localtime"] = 1 if localtime_var.get() else 0
                
                # K - RTC Start Date
                if rtc_startdate_var.get():
                    new_config["rtcstartdate"] = rtc_startdate_var.get()
                
                # L - SMBIOS
                if smbios1_var.get():
                    new_config["smbios1"] = smbios1_var.get()
                
                # M - QEMU Guest Agent
                new_config["agent"] = "enabled=1" if agent_enabled_var.get() else "enabled=0"
                
                # N - Protection
                new_config["protection"] = 1 if protection_var.get() else 0
                
                # O - Spice Enhancements
                if spice_enhancements_var.get():
                    new_config["spice_enhancements"] = spice_enhancements_var.get()
                
                # P - VM State Storage
                if vmstate_var.get():
                    new_config["vmstate"] = vmstate_var.get()
                
                # Q - AMD SEV
                if sev_var.get():
                    new_config["sev"] = sev_var.get()
                
                # Apply changes
                client.update_vm_config(node_name, vmid, new_config)
                
                def show_success() -> None:
                    from main import styled_info
                    styled_info("Options Saved", "VM options have been updated successfully.", parent)
                    go_back()
                parent.after(0, show_success)
                
            except ProxmoxAPIError as exc:
                def show_error() -> None:
                    from main import styled_error
                    styled_error("Save Failed", f"Failed to save VM options:\n{exc}", parent)
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
    
    # Load VM options
    parent.after(100, load_vm_options)

