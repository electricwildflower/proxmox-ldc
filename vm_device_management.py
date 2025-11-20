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


def show_device_management(
    parent: tk.Tk,
    account: dict,
    node_name: str,
    vmid: int,
    vm_name: str,
    rows_container: tk.Frame,
    render_vm_rows_func,
) -> None:
    """Show device management in the main window."""
    # Clear the rows container
    for child in rows_container.winfo_children():
        child.destroy()
    
    # Create a container for the device management view
    device_container = tk.Frame(rows_container, bg=PROXMOX_DARK)
    device_container.pack(fill=tk.BOTH, expand=True)
    
    # Header with back button
    header = tk.Frame(device_container, bg=PROXMOX_DARK)
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
        text=f"Device Management - {vm_name}",
        font=("Segoe UI", 20, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(20, 0))
    
    # Main content with scrollable canvas
    canvas = tk.Canvas(device_container, bg=PROXMOX_DARK, highlightthickness=0)
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
    canvas.focus_set()
    
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
    
    content = tk.Frame(scrollable_frame, bg=PROXMOX_DARK)
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    
    # Loading indicator
    loading_label = tk.Label(
        content,
        text="Loading device configuration...",
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    loading_label.pack(pady=20)
    
    # Device list container
    device_list_frame = tk.Frame(content, bg=PROXMOX_DARK)
    
    # Store device data
    device_list: list[dict[str, Any]] = []
    available_isos: list[str] = []
    available_storages: list[str] = []
    available_usb_devices: list[dict[str, Any]] = []
    available_pci_devices: list[dict[str, Any]] = []
    vm_config: dict[str, Any] = {}
    proxmox_cfg: dict[str, Any] = {}
    
    def load_device_config() -> None:
        """Load VM device configuration."""
        nonlocal vm_config, proxmox_cfg, available_isos, available_storages, available_usb_devices, available_pci_devices
        
        proxmox_cfg = _get_active_proxmox_config(account) or {}
        host = proxmox_cfg.get("host")
        username = proxmox_cfg.get("username")
        password = proxmox_cfg.get("password")
        verify_ssl = proxmox_cfg.get("verify_ssl", False)
        trusted_cert = proxmox_cfg.get("trusted_cert")
        trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")
        
        if not all([host, username, password, node_name]):
            loading_label.config(text="Unable to load configuration: missing credentials")
            return
        
        def worker() -> None:
            nonlocal vm_config, available_isos, available_storages, available_usb_devices, available_pci_devices
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
                
                # Get VM config
                vm_config = client.get_vm_config(node_name, vmid)
                
                # Get available ISOs and storages
                storages = client.get_node_storage(node_name)
                for storage in storages:
                    storage_name = storage.get("storage", "")
                    if storage_name:
                        available_storages.append(storage_name)
                        try:
                            storage_content = client.get_storage_content(node_name, storage_name)
                            for item in storage_content:
                                if item.get("content") == "iso":
                                    volid = item.get("volid", "")
                                    if volid:
                                        available_isos.append(volid)
                        except Exception:
                            pass
                
                # Get USB devices
                try:
                    usb_devices = client.get_node_usb_devices(node_name)
                    for usb in usb_devices:
                        vendor = usb.get("vendor", "")
                        product = usb.get("product", "")
                        usb_id = usb.get("id", "")
                        if usb_id:
                            device_name = f"{vendor} {product}".strip() or f"USB Device {usb_id}"
                            available_usb_devices.append({
                                "id": usb_id,
                                "name": device_name,
                                "vendor": vendor,
                                "product": product,
                            })
                except Exception:
                    pass
                
                # Get PCI devices
                try:
                    pci_devices = client.get_node_pci_devices(node_name)
                    for pci in pci_devices:
                        pci_id = pci.get("id", "")
                        if not pci_id:
                            continue
                        
                        # Proxmox API returns:
                        # - id: PCI address (e.g., "0000:00:05.0")
                        # - vendor: Hex vendor ID (e.g., "0x8086")
                        # - device: Hex device ID (e.g., "0x6f28")
                        # - vendor_name: Vendor name (e.g., "Intel Corporation")
                        # - device_name: Device name (e.g., "Xeon E7 v4/Xeon E5 v4/...")
                        
                        # Get vendor name - use vendor_name if available, otherwise use vendor hex ID
                        vendor = pci.get("vendor_name", "")
                        if not vendor or vendor.strip() == "":
                            vendor = pci.get("vendor", "Unknown Vendor")
                        
                        # Get device name - use device_name if available, otherwise use device hex ID
                        device_name = pci.get("device_name", "")
                        if not device_name or device_name.strip() == "":
                            device_name = pci.get("device", "Unknown Device")
                        
                        # Clean up vendor and device (remove extra whitespace)
                        vendor = vendor.strip() if vendor else "Unknown Vendor"
                        device_name = device_name.strip() if device_name else "Unknown Device"
                        
                        available_pci_devices.append({
                            "id": pci_id,
                            "name": f"{vendor} {device_name}".strip() or f"PCI Device {pci_id}",
                            "vendor": vendor,
                            "device": device_name,
                        })
                except Exception as e:
                    # Log error for debugging
                    import sys
                    print(f"Error loading PCI devices: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc()
                    pass
                
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
                        text=f"Error loading configuration: {error_msg}",
                        font=("Segoe UI", 11),
                        fg="#f44336",
                        bg=PROXMOX_DARK,
                    ).pack(pady=20)
                    return
                
                # Parse devices
                device_keys_map: dict[str, str] = {}
                
                for key in vm_config.keys():
                    if key.startswith(("scsi", "virtio", "ide", "sata", "usb", "hostpci")):
                        base_key = key
                    elif key.startswith("unused") and any(key[6:].startswith(prefix) for prefix in ("scsi", "virtio", "ide", "sata", "usb", "hostpci")):
                        base_key = key[6:]
                    else:
                        continue
                    device_keys_map[base_key] = key
                
                for base_key in sorted(device_keys_map.keys()):
                    actual_key = device_keys_map[base_key]
                    value = str(vm_config.get(actual_key, ""))
                    
                    # Determine device type
                    if base_key.startswith("usb"):
                        device_type = "USB"
                    elif base_key.startswith("hostpci"):
                        device_type = "PCI"
                    elif "media=cdrom" in value.lower() or "cdrom" in value.lower():
                        device_type = "CD/DVD"
                    else:
                        device_type = "Disk"
                    
                    device_list.append({
                        "key": base_key,
                        "value": value,
                        "type": device_type,
                        "enabled": not actual_key.startswith("unused"),
                        "actual_key": actual_key,
                    })
                
                render_device_list()
                device_list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
                update_scrollregion()
            
            parent.after(0, update_ui)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def render_device_list() -> None:
        """Render the device list."""
        # Clear existing content
        for widget in device_list_frame.winfo_children():
            widget.destroy()
        
        # Section title
        tk.Label(
            device_list_frame,
            text="Devices",
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        ).pack(anchor=tk.W, pady=(0, 10))
        
        if not device_list:
            tk.Label(
                device_list_frame,
                text="No devices configured",
                font=("Segoe UI", 11),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
            ).pack(pady=20)
        else:
            # Header row
            header_row = tk.Frame(device_list_frame, bg=PROXMOX_MEDIUM)
            header_row.pack(fill=tk.X, pady=(0, 10))
            
            headers = ["Order", "Device", "Type", "Details", "Actions"]
            widths = [8, 12, 10, 30, 15]
            for header, width in zip(headers, widths):
                tk.Label(
                    header_row,
                    text=header,
                    font=("Segoe UI", 10, "bold"),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                    width=width,
                ).pack(side=tk.LEFT, padx=(0, 5))
            
            # Device rows
            device_rows: list[tk.Frame] = []
            
            for idx, device in enumerate(device_list):
                row = tk.Frame(device_list_frame, bg=PROXMOX_MEDIUM)
                row.pack(fill=tk.X, pady=4)
                device_rows.append(row)
                
                # Order
                tk.Label(
                    row,
                    text=str(idx + 1),
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=8,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                # Device key
                tk.Label(
                    row,
                    text=device["key"],
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=12,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                # Device type
                tk.Label(
                    row,
                    text=device["type"],
                    font=("Segoe UI", 10),
                    fg="#cfd3da",
                    bg=PROXMOX_MEDIUM,
                    width=10,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                # Device details/ISO selector
                details_frame = tk.Frame(row, bg=PROXMOX_MEDIUM)
                details_frame.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
                
                if device["type"] == "CD/DVD":
                    iso_var = tk.StringVar()
                    current_iso = device["value"].split(",")[0] if "," in device["value"] else device["value"]
                    iso_var.set(current_iso)
                    
                    iso_values = [current_iso] + [iso for iso in available_isos if iso != current_iso]
                    
                    iso_combobox = ttk.Combobox(
                        details_frame,
                        textvariable=iso_var,
                        values=iso_values,
                        state="readonly",
                        width=25,
                    )
                    
                    style = ttk.Style()
                    style.theme_use("clam")
                    style.configure(
                        "Custom.TCombobox",
                        fieldbackground=PROXMOX_DARK,
                        background=PROXMOX_DARK,
                        foreground=PROXMOX_LIGHT,
                        borderwidth=0,
                        relief="flat",
                    )
                    style.map(
                        "Custom.TCombobox",
                        fieldbackground=[("readonly", PROXMOX_DARK)],
                        background=[("readonly", PROXMOX_DARK)],
                        foreground=[("readonly", PROXMOX_LIGHT)],
                    )
                    iso_combobox.configure(style="Custom.TCombobox")
                    iso_combobox.pack(side=tk.LEFT, fill=tk.X, expand=True)
                    
                    device["iso_var"] = iso_var
                elif device["type"] in ["USB", "PCI"]:
                    # Show device info for USB/PCI
                    device_info = device["value"][:40] + "..." if len(device["value"]) > 40 else device["value"]
                    tk.Label(
                        details_frame,
                        text=device_info,
                        font=("Segoe UI", 9),
                        fg="#cfd3da",
                        bg=PROXMOX_MEDIUM,
                        anchor="w",
                    ).pack(side=tk.LEFT, fill=tk.X, expand=True)
                else:
                    disk_info = device["value"][:40] + "..." if len(device["value"]) > 40 else device["value"]
                    tk.Label(
                        details_frame,
                        text=disk_info,
                        font=("Segoe UI", 9),
                        fg="#cfd3da",
                        bg=PROXMOX_MEDIUM,
                        anchor="w",
                    ).pack(side=tk.LEFT, fill=tk.X, expand=True)
                
                # Actions (reorder buttons)
                actions_frame = tk.Frame(row, bg=PROXMOX_MEDIUM)
                actions_frame.pack(side=tk.LEFT)
                
                def move_up(i: int) -> None:
                    if i > 0:
                        device_list[i], device_list[i - 1] = device_list[i - 1], device_list[i]
                        render_device_list()
                        update_scrollregion()
                
                def move_down(i: int) -> None:
                    if i < len(device_list) - 1:
                        device_list[i], device_list[i + 1] = device_list[i + 1], device_list[i]
                        render_device_list()
                        update_scrollregion()
                
                if idx > 0:
                    tk.Button(
                        actions_frame,
                        text="↑",
                        command=lambda i=idx: move_up(i),
                        font=("Segoe UI", 9, "bold"),
                        bg=PROXMOX_DARK,
                        fg=PROXMOX_LIGHT,
                        activebackground=PROXMOX_ORANGE,
                        activeforeground="white",
                        bd=0,
                        width=3,
                        padx=4,
                        pady=2,
                    ).pack(side=tk.LEFT, padx=1)
                
                if idx < len(device_list) - 1:
                    tk.Button(
                        actions_frame,
                        text="↓",
                        command=lambda i=idx: move_down(i),
                        font=("Segoe UI", 9, "bold"),
                        bg=PROXMOX_DARK,
                        fg=PROXMOX_LIGHT,
                        activebackground=PROXMOX_ORANGE,
                        activeforeground="white",
                        bd=0,
                        width=3,
                        padx=4,
                        pady=2,
                    ).pack(side=tk.LEFT, padx=1)
        
        # Add device section
        add_device_section = tk.Frame(device_list_frame, bg=PROXMOX_DARK)
        add_device_section.pack(fill=tk.X, pady=(30, 10))
        
        tk.Label(
            add_device_section,
            text="Add New Device",
            font=("Segoe UI", 14, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        ).pack(anchor=tk.W, pady=(0, 10))
        
        add_device_frame = tk.Frame(add_device_section, bg=PROXMOX_MEDIUM)
        add_device_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Device type selection
        tk.Label(
            add_device_frame,
            text="Device Type:",
            font=("Segoe UI", 10),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=15, pady=10)
        
        device_type_var = tk.StringVar(value="CD/DVD")
        device_type_menu = ttk.Combobox(
            add_device_frame,
            textvariable=device_type_var,
            values=["CD/DVD", "Hard Drive", "USB", "PCI"],
            state="readonly",
            width=15,
        )
        device_type_menu.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Device configuration frame (changes based on type)
        device_config_frame = tk.Frame(add_device_frame, bg=PROXMOX_MEDIUM)
        device_config_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10)
        
        def update_device_config_ui() -> None:
            """Update the device configuration UI based on selected type."""
            for widget in device_config_frame.winfo_children():
                widget.destroy()
            
            device_type = device_type_var.get()
            
            if device_type == "CD/DVD":
                tk.Label(
                    device_config_frame,
                    text="ISO Image:",
                    font=("Segoe UI", 10),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                iso_select_var = tk.StringVar()
                iso_select = ttk.Combobox(
                    device_config_frame,
                    textvariable=iso_select_var,
                    values=available_isos if available_isos else ["No ISOs available"],
                    state="readonly" if available_isos else "disabled",
                    width=40,
                )
                iso_select.pack(side=tk.LEFT, fill=tk.X, expand=True)
                device_config_frame.iso_var = iso_select_var
                
            elif device_type == "Hard Drive":
                tk.Label(
                    device_config_frame,
                    text="Size (GB):",
                    font=("Segoe UI", 10),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                size_entry = tk.Entry(
                    device_config_frame,
                    font=("Segoe UI", 10),
                    bg=PROXMOX_DARK,
                    fg=PROXMOX_LIGHT,
                    insertbackground=PROXMOX_LIGHT,
                    width=15,
                )
                size_entry.pack(side=tk.LEFT, padx=(0, 10))
                device_config_frame.size_var = size_entry
                
                tk.Label(
                    device_config_frame,
                    text="Storage:",
                    font=("Segoe UI", 10),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                storage_var = tk.StringVar()
                storage_select = ttk.Combobox(
                    device_config_frame,
                    textvariable=storage_var,
                    values=available_storages if available_storages else ["No storage available"],
                    state="readonly" if available_storages else "disabled",
                    width=20,
                )
                storage_select.pack(side=tk.LEFT, fill=tk.X, expand=True)
                device_config_frame.storage_var = storage_var
                
            elif device_type == "USB":
                tk.Label(
                    device_config_frame,
                    text="USB Device:",
                    font=("Segoe UI", 10),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                usb_var = tk.StringVar()
                usb_values = [f"{usb['name']} ({usb['id']})" for usb in available_usb_devices]
                if not usb_values:
                    usb_values = ["No USB devices available"]
                
                usb_select = ttk.Combobox(
                    device_config_frame,
                    textvariable=usb_var,
                    values=usb_values,
                    state="readonly" if available_usb_devices else "disabled",
                    width=40,
                )
                usb_select.pack(side=tk.LEFT, fill=tk.X, expand=True)
                device_config_frame.usb_var = usb_var
                
            elif device_type == "PCI":
                tk.Label(
                    device_config_frame,
                    text="PCI Device:",
                    font=("Segoe UI", 10),
                    fg=PROXMOX_LIGHT,
                    bg=PROXMOX_MEDIUM,
                ).pack(side=tk.LEFT, padx=(0, 5))
                
                pci_var = tk.StringVar()
                pci_values = []
                for pci in available_pci_devices:
                    pci_id = pci.get('id', 'Unknown ID') or 'Unknown ID'
                    vendor = pci.get('vendor', '') or 'Unknown Vendor'
                    device = pci.get('device', '') or 'Unknown Device'
                    # Ensure we have non-empty values
                    if not vendor or vendor.strip() == '':
                        vendor = 'Unknown Vendor'
                    if not device or device.strip() == '':
                        device = 'Unknown Device'
                    pci_values.append(f"{pci_id} - {vendor} - {device}")
                if not pci_values:
                    pci_values = ["No PCI devices available"]
                
                pci_select = ttk.Combobox(
                    device_config_frame,
                    textvariable=pci_var,
                    values=pci_values,
                    state="readonly" if available_pci_devices else "disabled",
                    width=40,
                )
                pci_select.pack(side=tk.LEFT, fill=tk.X, expand=True)
                device_config_frame.pci_var = pci_var
        
        device_type_var.trace_add("write", lambda *args: update_device_config_ui())
        update_device_config_ui()
        
        # Add button
        def add_device() -> None:
            """Add a new device to the list."""
            device_type = device_type_var.get()
            
            # Find next available device slot
            existing_keys = [d["key"] for d in device_list]
            device_bus = "ide"  # Default bus
            device_num = 0
            
            # Find next available number
            while True:
                test_key = f"{device_bus}{device_num}"
                if test_key not in existing_keys:
                    break
                device_num += 1
                if device_num > 10:  # Try different bus
                    if device_bus == "ide":
                        device_bus = "sata"
                        device_num = 0
                    elif device_bus == "sata":
                        device_bus = "scsi"
                        device_num = 0
                    else:
                        device_bus = "virtio"
                        device_num = 0
            
            # Default device key (will be overridden for USB/PCI)
            new_device_key = f"{device_bus}{device_num}"
            device_value = ""
            iso_var_ref = None
            
            if device_type == "CD/DVD":
                iso_var = getattr(device_config_frame, "iso_var", None)
                if iso_var and iso_var.get():
                    device_value = f"{iso_var.get()},media=cdrom"
                    iso_var_ref = tk.StringVar(value=iso_var.get())
                else:
                    from main import styled_warning
                    styled_warning("No ISO Selected", "Please select an ISO image for the CD/DVD drive.")
                    return
            elif device_type == "Hard Drive":
                size_var = getattr(device_config_frame, "size_var", None)
                storage_var = getattr(device_config_frame, "storage_var", None)
                if size_var and storage_var:
                    try:
                        size_gb = int(size_var.get())
                        if size_gb <= 0:
                            raise ValueError("Size must be positive")
                        storage = storage_var.get()
                        if storage and storage != "No storage available" and storage != "Loading...":
                            device_value = f"{storage}:{size_gb}"
                        else:
                            from main import styled_warning
                            styled_warning("Invalid Storage", "Please select a storage pool.")
                            return
                    except ValueError:
                        from main import styled_warning
                        styled_warning("Invalid Size", "Please enter a valid size in GB (positive number).")
                        return
                else:
                    from main import styled_warning
                    styled_warning("Missing Information", "Please enter size and select storage.")
                    return
            elif device_type == "USB":
                usb_var = getattr(device_config_frame, "usb_var", None)
                if usb_var and usb_var.get():
                    selected = usb_var.get()
                    # Extract USB ID from selection (format: "Name (id)")
                    if "(" in selected and ")" in selected:
                        usb_id = selected.split("(")[1].split(")")[0]
                        # Proxmox USB format: host=usb_id
                        device_value = f"host={usb_id}"
                        # Use usb0, usb1, etc. for USB devices
                        # Find next USB slot
                        usb_num = 0
                        while f"usb{usb_num}" in existing_keys:
                            usb_num += 1
                        new_device_key = f"usb{usb_num}"
                    else:
                        from main import styled_warning
                        styled_warning("Invalid USB Device", "Please select a USB device.")
                        return
                else:
                    from main import styled_warning
                    styled_warning("No USB Device Selected", "Please select a USB device.")
                    return
            elif device_type == "PCI":
                pci_var = getattr(device_config_frame, "pci_var", None)
                if pci_var and pci_var.get():
                    selected = pci_var.get()
                    # Extract PCI ID from selection (format: "ID - Vendor - Device")
                    if " - " in selected:
                        pci_id = selected.split(" - ")[0].strip()
                        # Proxmox PCI format: host=pci_id
                        device_value = f"host={pci_id}"
                        # Use hostpci0, hostpci1, etc. for PCI devices
                        # Find next PCI slot
                        pci_num = 0
                        while f"hostpci{pci_num}" in existing_keys:
                            pci_num += 1
                        new_device_key = f"hostpci{pci_num}"
                    else:
                        from main import styled_warning
                        styled_warning("Invalid PCI Device", "Please select a PCI device.")
                        return
                else:
                    from main import styled_warning
                    styled_warning("No PCI Device Selected", "Please select a PCI device.")
                    return
            
            # Create device dict
            new_device: dict[str, Any] = {
                "key": new_device_key,
                "value": device_value,
                "type": device_type,
                "enabled": True,
                "actual_key": new_device_key,
            }
            
            if iso_var_ref:
                new_device["iso_var"] = iso_var_ref
            
            device_list.append(new_device)
            render_device_list()
            update_scrollregion()
        
        tk.Button(
            add_device_frame,
            text="Add Device",
            command=add_device,
            font=("Segoe UI", 10, "bold"),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            activeforeground="white",
            bd=0,
            padx=12,
            pady=6,
        ).pack(side=tk.RIGHT, padx=15, pady=10)
        
        update_scrollregion()
    
    def save_changes() -> None:
        """Save device configuration changes."""
        # Check if VM is running
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
                
                # Check VM status
                vms = client.get_node_vms(node_name)
                vm_runtime = next((vm for vm in vms if vm.get("vmid") == vmid), None)
                if vm_runtime and vm_runtime.get("status") == "running":
                    from main import styled_warning
                    styled_warning(
                        "VM Running",
                        "Cannot modify device configuration while VM is running. Please stop the VM first."
                    )
                    return
                
                # Build new config
                new_config: dict[str, Any] = {}
                delete_keys: list[str] = []
                
                # Process devices in new order
                for device in device_list:
                    device_key = device["key"]
                    
                    if device["type"] == "CD/DVD" and "iso_var" in device:
                        new_iso = device["iso_var"].get()
                        original_parts = device.get("value", "").split(",")
                        new_parts = [new_iso]
                        for part in original_parts[1:]:
                            if part.strip():
                                new_parts.append(part.strip())
                        new_config[device_key] = ",".join(new_parts)
                    else:
                        new_config[device_key] = device.get("value", "")
                
                # Update boot order (exclude USB and PCI devices)
                boot_order = []
                for device in device_list:
                    if device.get("enabled", True):
                        device_key = device["key"]
                        device_type = device.get("type", "")
                        # USB and PCI devices don't participate in boot order
                        if device_type in ["USB", "PCI"]:
                            continue
                        if device_key.startswith("scsi"):
                            device_num = device_key[4:].split(":")[0] if ":" in device_key else device_key[4:]
                            boot_order.append(f"scsi{device_num}")
                        elif device_key.startswith("virtio"):
                            device_num = device_key[6:].split(":")[0] if ":" in device_key else device_key[6:]
                            boot_order.append(f"virtio{device_num}")
                        elif device_key.startswith("ide"):
                            device_num = device_key[3:].split(":")[0] if ":" in device_key else device_key[3:]
                            boot_order.append(f"ide{device_num}")
                        elif device_key.startswith("sata"):
                            device_num = device_key[4:].split(":")[0] if ":" in device_key else device_key[4:]
                            boot_order.append(f"sata{device_num}")
                
                if boot_order:
                    new_config["boot"] = "order=" + ";".join(boot_order)
                
                # Apply changes
                client.update_vm_config(node_name, vmid, new_config)
                
                from main import styled_info
                styled_info("Changes Saved", "Device configuration has been updated successfully.")
                go_back()
                
            except ProxmoxAPIError as exc:
                from main import styled_error
                styled_error("Save Failed", f"Failed to save device changes:\n{exc}")
            except Exception as exc:
                from main import styled_error
                styled_error("Save Failed", f"Error: {exc}")
            finally:
                if client:
                    client.close()
        
        threading.Thread(target=check_and_save, daemon=True).start()
    
    # Footer with save button
    footer = tk.Frame(device_container, bg=PROXMOX_DARK)
    footer.pack(fill=tk.X, padx=20, pady=(0, 20))
    
    tk.Button(
        footer,
        text="Save Changes",
        command=save_changes,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.RIGHT)
    
    # Load device config
    parent.after(100, load_device_config)
