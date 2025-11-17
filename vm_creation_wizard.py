import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from proxmox_client import ProxmoxAPIError, ProxmoxClient
from theme import (
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
)


def _styled_error(parent: tk.Widget, title: str, message: str) -> None:
    """Show a styled error dialog matching the app theme."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 250
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 100
    dialog.geometry(f"500x180+{x}+{y}")

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
        wraplength=450,
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


def _styled_info(parent: tk.Widget, title: str, message: str) -> None:
    """Show a styled info dialog matching the app theme."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Center the dialog
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 250
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 100
    dialog.geometry(f"500x180+{x}+{y}")

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
        wraplength=450,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=24, pady=(0, 16))

    actions = tk.Frame(dialog, bg=PROXMOX_DARK)
    actions.pack(fill=tk.X, padx=24, pady=(0, 20))

    tk.Button(
        actions,
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
    ).pack(side=tk.RIGHT)

    dialog.wait_window()


class VMCreationWizard(tk.Frame):
    def __init__(
        self,
        master: tk.Widget,
        proxmox_config: dict[str, Any],
        on_complete: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__(master, bg=PROXMOX_DARK)
        self.proxmox_config = proxmox_config
        self.on_complete = on_complete
        self.current_step = 0
        self.client: ProxmoxClient | None = None
        self.nodes: list[dict[str, Any]] = []
        self.storages: list[dict[str, Any]] = []
        self.isos: list[dict[str, Any]] = []
        self.networks: list[dict[str, Any]] = []
        self.selected_node: str = ""

        self._configure_style()
        self._create_variables()
        self._build_ui()
        self._load_data()
        self._show_step(0)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "Wizard.TFrame",
            padding=20,
            background=PROXMOX_DARK,
        )
        style.configure(
            "Wizard.Card.TFrame",
            padding=25,
            background=PROXMOX_MEDIUM,
            relief="flat",
        )
        style.configure(
            "Wizard.TLabel",
            font=("Segoe UI", 11),
            foreground=PROXMOX_LIGHT,
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "WizardHeader.TLabel",
            font=("Segoe UI", 18, "bold"),
            foreground=PROXMOX_LIGHT,
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "Wizard.SubHeader.TLabel",
            font=("Segoe UI", 12),
            foreground="#b0b6bf",
            background=PROXMOX_MEDIUM,
        )
        style.configure(
            "Wizard.TButton",
            font=("Segoe UI", 11, "bold"),
            background=PROXMOX_ORANGE,
            foreground="white",
            padding=10,
            borderwidth=0,
        )
        style.map(
            "Wizard.TButton",
            background=[("active", "#ff8126"), ("disabled", "#666")],
        )
        style.configure(
            "Wizard.Secondary.TButton",
            font=("Segoe UI", 11),
            background=PROXMOX_MEDIUM,
            foreground=PROXMOX_LIGHT,
            bordercolor=PROXMOX_LIGHT,
            padding=10,
        )
        style.map(
            "Wizard.Secondary.TButton",
            background=[("active", "#353c45")],
        )
        style.configure(
            "Wizard.TEntry",
            fieldbackground="#1f242b",
            background="#1f242b",
            foreground=PROXMOX_LIGHT,
            bordercolor="#363c45",
            insertcolor=PROXMOX_LIGHT,
            padding=8,
        )
        style.configure(
            "Wizard.TCombobox",
            fieldbackground="#1f242b",
            background="#1f242b",
            foreground=PROXMOX_LIGHT,
            bordercolor="#363c45",
            padding=8,
        )

        self.configure(bg=PROXMOX_DARK)

    def _create_variables(self) -> None:
        self.vm_name_var = tk.StringVar()
        self.vmid_var = tk.StringVar()
        self.node_var = tk.StringVar()
        self.cpu_cores_var = tk.StringVar(value="2")
        self.memory_var = tk.StringVar(value="2048")
        self.disk_size_var = tk.StringVar(value="32")
        self.storage_var = tk.StringVar()
        self.iso_var = tk.StringVar()
        self.bridge_var = tk.StringVar(value="vmbr0")

    def _build_ui(self) -> None:
        header_wrapper = ttk.Frame(self, style="Wizard.TFrame")
        header_wrapper.pack(fill=tk.X, padx=30, pady=(20, 10))

        title = ttk.Label(
            header_wrapper,
            text="Create Virtual Machine",
            font=("Segoe UI", 24, "bold"),
            foreground=PROXMOX_ORANGE,
            background=PROXMOX_DARK,
        )
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            header_wrapper,
            text="Configure a new virtual machine for your Proxmox server.",
            font=("Segoe UI", 12),
            foreground="#b0b6bf",
            background=PROXMOX_DARK,
        )
        subtitle.pack(anchor=tk.W, pady=(4, 0))

        content_frame = ttk.Frame(self, style="Wizard.TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 10))

        self.card = ttk.Frame(content_frame, style="Wizard.Card.TFrame")
        self.card.pack(fill=tk.BOTH, expand=True)

        self.container = ttk.Frame(self.card, style="Wizard.Card.TFrame")
        self.container.pack(fill=tk.BOTH, expand=True)

        self.steps = [
            self._build_basic_step(),
            self._build_resources_step(),
            self._build_storage_step(),
            self._build_network_step(),
        ]

        nav_frame = ttk.Frame(self.card, style="Wizard.Card.TFrame")
        nav_frame.pack(fill=tk.X, pady=(20, 0))

        self.step_indicator = ttk.Label(
            nav_frame,
            text="Step 1 of 4",
            style="Wizard.SubHeader.TLabel",
            background=PROXMOX_MEDIUM,
        )
        self.step_indicator.pack(side=tk.LEFT)

        button_group = ttk.Frame(nav_frame, style="Wizard.Card.TFrame")
        button_group.pack(side=tk.RIGHT)

        self.back_button = ttk.Button(
            button_group,
            text="Back",
            command=self._previous_step,
            style="Wizard.Secondary.TButton",
        )
        self.back_button.pack(side=tk.LEFT, padx=(0, 10))

        self.next_button = ttk.Button(
            button_group,
            text="Next",
            command=self._next_step,
            style="Wizard.TButton",
        )
        self.next_button.pack(side=tk.LEFT)

    def _build_basic_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Basic Information", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Provide basic details for the new virtual machine.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self._add_labeled_entry(frame, "VM Name", self.vm_name_var)
        self._add_labeled_entry(frame, "VM ID (leave empty for auto)", self.vmid_var)

        # Node selection
        ttk.Label(frame, text="Node", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.node_combo = ttk.Combobox(
            frame,
            textvariable=self.node_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.node_combo.pack(fill=tk.X, pady=(0, 5))
        self.node_combo.bind("<<ComboboxSelected>>", self._on_node_selected)

        return frame

    def _build_resources_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Resources", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Configure CPU and memory allocation.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self._add_labeled_entry(frame, "CPU Cores", self.cpu_cores_var)
        self._add_labeled_entry(frame, "Memory (MB)", self.memory_var)

        return frame

    def _build_storage_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Storage", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Configure disk storage and optional ISO image.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        self._add_labeled_entry(frame, "Disk Size (GB)", self.disk_size_var)

        ttk.Label(frame, text="Storage", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.storage_combo = ttk.Combobox(
            frame,
            textvariable=self.storage_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.storage_combo.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(frame, text="ISO Image (optional)", style="Wizard.TLabel").pack(
            anchor=tk.W, pady=(5, 2)
        )
        self.iso_combo = ttk.Combobox(
            frame,
            textvariable=self.iso_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.iso_combo.pack(fill=tk.X, pady=(0, 5))

        return frame

    def _build_network_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.container, style="Wizard.Card.TFrame")

        ttk.Label(frame, text="Network", style="WizardHeader.TLabel").pack(
            anchor=tk.W, pady=(0, 4)
        )
        ttk.Label(
            frame,
            text="Configure network bridge for the virtual machine.",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        ttk.Label(frame, text="Bridge", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.bridge_combo = ttk.Combobox(
            frame,
            textvariable=self.bridge_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.bridge_combo.pack(fill=tk.X, pady=(0, 5))

        return frame

    def _add_labeled_entry(
        self,
        parent: ttk.Frame,
        label_text: str,
        variable: tk.StringVar,
        show: str | None = None,
    ) -> None:
        label = ttk.Label(parent, text=label_text, style="Wizard.TLabel")
        label.pack(anchor=tk.W, pady=(5, 2))
        entry = ttk.Entry(parent, textvariable=variable, show=show or "", style="Wizard.TEntry")
        entry.pack(fill=tk.X, pady=(0, 5))

    def _load_data(self) -> None:
        """Load nodes, storages, and networks from Proxmox."""
        def worker() -> None:
            try:
                client = ProxmoxClient(
                    host=self.proxmox_config["host"],
                    username=self.proxmox_config["username"],
                    password=self.proxmox_config["password"],
                    verify_ssl=self.proxmox_config.get("verify_ssl", False),
                    trusted_cert=self.proxmox_config.get("trusted_cert"),
                    trusted_fingerprint=self.proxmox_config.get("trusted_cert_fingerprint"),
                )
                self.client = client

                # Load nodes
                nodes = client.get_nodes()
                self.nodes = nodes
                node_names = [n.get("node", "") for n in nodes if n.get("node")]
                
                # Load networks (from first node if available)
                networks = []
                if node_names:
                    networks = client.get_node_network(node_names[0])
                    self.networks = networks
                    bridge_names = [
                        n.get("iface", "") for n in networks
                        if n.get("type") == "bridge" and n.get("iface")
                    ]
                    if bridge_names:
                        self.bridge_var.set(bridge_names[0])

                def update_ui() -> None:
                    if node_names:
                        self.node_combo["values"] = node_names
                        self.node_var.set(node_names[0])
                        self.selected_node = node_names[0]
                        self._load_node_data(node_names[0])
                    
                    if networks:
                        bridge_names = [
                            n.get("iface", "") for n in networks
                            if n.get("type") == "bridge" and n.get("iface")
                        ]
                        if bridge_names:
                            self.bridge_combo["values"] = bridge_names
                            if not self.bridge_var.get():
                                self.bridge_var.set(bridge_names[0])

                self.after(0, update_ui)
            except Exception as exc:
                def show_error() -> None:
                    _styled_error(
                        self,
                        "Connection Error",
                        f"Unable to connect to Proxmox server:\n{exc}",
                    )
                self.after(0, show_error)

        threading.Thread(target=worker, daemon=True).start()

    def _on_node_selected(self, event: tk.Event) -> None:
        """Handle node selection change."""
        node = self.node_var.get()
        if node:
            self.selected_node = node
            self._load_node_data(node)

    def _load_node_data(self, node: str) -> None:
        """Load storage and ISO data for the selected node."""
        if not self.client:
            return

        def worker() -> None:
            try:
                # Load storages
                storages = self.client.get_node_storage(node)
                self.storages = storages
                storage_names = [
                    s.get("storage", "") for s in storages
                    if s.get("type") in ("dir", "lvm", "lvmthin", "zfspool", "rbd")
                    and s.get("storage")
                ]

                # Load ISOs from first storage that supports ISOs
                isos = []
                iso_storage = None
                for storage in storages:
                    if storage.get("content") and "iso" in storage.get("content", ""):
                        iso_storage = storage.get("storage")
                        try:
                            content = self.client.get_storage_content(node, iso_storage)
                            isos = [
                                item.get("volid", "").split("/")[-1]
                                for item in content
                                if item.get("content") == "iso" and item.get("volid")
                            ]
                            break
                        except Exception:
                            continue

                def update_ui() -> None:
                    if storage_names:
                        self.storage_combo["values"] = storage_names
                        if not self.storage_var.get():
                            self.storage_var.set(storage_names[0])
                    
                    if isos:
                        self.iso_combo["values"] = [""] + isos
                    else:
                        self.iso_combo["values"] = [""]

                self.after(0, update_ui)
            except Exception:
                pass  # Silently fail for storage/ISO loading

        threading.Thread(target=worker, daemon=True).start()

    def _show_step(self, index: int) -> None:
        for frame in self.steps:
            frame.pack_forget()
        self.steps[index].pack(fill=tk.BOTH, expand=True)
        self.current_step = index
        self.back_button["state"] = tk.NORMAL if index > 0 else tk.DISABLED
        self.next_button["text"] = "Create" if index == len(self.steps) - 1 else "Next"
        self.step_indicator.config(text=f"Step {index + 1} of {len(self.steps)}")

    def _next_step(self) -> None:
        if not self._validate_current_step():
            return

        if self.current_step == len(self.steps) - 1:
            self._create_vm()
        else:
            self._show_step(self.current_step + 1)

    def _previous_step(self) -> None:
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    def _validate_current_step(self) -> bool:
        if self.current_step == 0:
            vm_name = self.vm_name_var.get().strip()
            node = self.node_var.get().strip()

            if not vm_name:
                _styled_error(self, "Missing information", "VM name is required.")
                return False

            if not node:
                _styled_error(self, "Missing information", "Please select a node.")
                return False

        elif self.current_step == 1:
            try:
                cpu = int(self.cpu_cores_var.get().strip())
                memory = int(self.memory_var.get().strip())
                if cpu < 1:
                    raise ValueError("CPU must be at least 1")
                if memory < 128:
                    raise ValueError("Memory must be at least 128 MB")
            except ValueError as exc:
                _styled_error(
                    self,
                    "Invalid input",
                    f"Please enter valid numbers:\n{exc}",
                )
                return False

        elif self.current_step == 2:
            try:
                disk_size = int(self.disk_size_var.get().strip())
                if disk_size < 1:
                    raise ValueError("Disk size must be at least 1 GB")
            except ValueError as exc:
                _styled_error(
                    self,
                    "Invalid input",
                    f"Please enter a valid disk size:\n{exc}",
                )
                return False

            if not self.storage_var.get().strip():
                _styled_error(self, "Missing information", "Please select a storage.")
                return False

        elif self.current_step == 3:
            if not self.bridge_var.get().strip():
                _styled_error(self, "Missing information", "Please select a bridge.")
                return False

        return True

    def _create_vm(self) -> None:
        """Create the VM with the configured settings."""
        def worker() -> None:
            client: ProxmoxClient | None = None
            try:
                # Create a new client for this operation
                client = ProxmoxClient(
                    host=self.proxmox_config["host"],
                    username=self.proxmox_config["username"],
                    password=self.proxmox_config["password"],
                    verify_ssl=self.proxmox_config.get("verify_ssl", False),
                    trusted_cert=self.proxmox_config.get("trusted_cert"),
                    trusted_fingerprint=self.proxmox_config.get("trusted_cert_fingerprint"),
                )
                # Get or generate VM ID
                vmid_str = self.vmid_var.get().strip()
                if vmid_str:
                    try:
                        vmid = int(vmid_str)
                    except ValueError:
                        def show_error() -> None:
                            _styled_error(self, "Invalid VM ID", "VM ID must be a number.")
                        self.after(0, show_error)
                        return
                else:
                    vmid = client.get_next_vmid()

                node = self.node_var.get().strip()
                vm_name = self.vm_name_var.get().strip()
                cpu_cores = int(self.cpu_cores_var.get().strip())
                memory_mb = int(self.memory_var.get().strip())
                disk_size_gb = int(self.disk_size_var.get().strip())
                storage = self.storage_var.get().strip()
                iso = self.iso_var.get().strip()
                bridge = self.bridge_var.get().strip()

                # Build VM config
                config: dict[str, Any] = {
                    "name": vm_name,
                    "cores": cpu_cores,
                    "memory": memory_mb,
                    "net0": f"virtio,bridge={bridge}",
                    f"scsi0": f"{storage}:{disk_size_gb}",
                }

                if iso:
                    # Find the storage that contains the ISO and get the full volid
                    for s in self.storages:
                        if s.get("content") and "iso" in s.get("content", ""):
                            try:
                                content = client.get_storage_content(node, s.get("storage", ""))
                                for item in content:
                                    volid = item.get("volid", "")
                                    if item.get("content") == "iso" and volid.endswith(iso):
                                        # Use the full volid from the API
                                        config["ide2"] = f"{volid},media=cdrom"
                                        break
                                if "ide2" in config:
                                    break
                            except Exception:
                                continue

                # Create the VM
                client.create_vm(node, vmid, config)

                def show_success() -> None:
                    _styled_info(
                        self,
                        "Success",
                        f"Virtual machine '{vm_name}' (ID: {vmid}) has been created successfully.",
                    )
                    if self.on_complete:
                        self.on_complete({"vmid": vmid, "node": node, "name": vm_name})
                    # Reset form for creating another VM
                    self.after(1000, self._reset_form)

                self.after(0, show_success)
            except ProxmoxAPIError as exc:
                def show_error() -> None:
                    _styled_error(
                        self,
                        "Creation Failed",
                        f"Unable to create virtual machine:\n{exc}",
                    )
                self.after(0, show_error)
            except Exception as exc:
                def show_error() -> None:
                    _styled_error(
                        self,
                        "Error",
                        f"An unexpected error occurred:\n{exc}",
                    )
                self.after(0, show_error)
            finally:
                if client:
                    client.close()

        threading.Thread(target=worker, daemon=True).start()

    def _reset_form(self) -> None:
        """Reset the form to initial state for creating another VM."""
        self.vm_name_var.set("")
        self.vmid_var.set("")
        self.cpu_cores_var.set("2")
        self.memory_var.set("2048")
        self.disk_size_var.set("32")
        self.storage_var.set("")
        self.iso_var.set("")
        if self.nodes:
            node_names = [n.get("node", "") for n in self.nodes if n.get("node")]
            if node_names:
                self.node_var.set(node_names[0])
        self._show_step(0)

