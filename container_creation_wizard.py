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


class ContainerCreationWizard(tk.Frame):
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
        self.templates: list[str] = []
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
            background=[("active", "#3a414d")],
        )
        style.configure(
            "Wizard.TEntry",
            fieldbackground="#1f242b",
            foreground=PROXMOX_LIGHT,
            bordercolor="#363c45",
            insertcolor=PROXMOX_LIGHT,
            padding=8,
        )
        style.configure(
            "Wizard.TCombobox",
            fieldbackground="#1f242b",
            foreground=PROXMOX_LIGHT,
            bordercolor="#363c45",
            padding=8,
        )

    def _create_variables(self) -> None:
        self.ctid_var = tk.StringVar()
        self.hostname_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.password_confirm_var = tk.StringVar()
        self.node_var = tk.StringVar()
        self.template_var = tk.StringVar()
        self.storage_var = tk.StringVar()
        self.disk_size_var = tk.StringVar(value="8")
        self.cpu_cores_var = tk.StringVar(value="1")
        self.memory_var = tk.StringVar(value="512")
        self.bridge_var = tk.StringVar()
        self.template_choices: dict[str, str] = {}

    def _build_ui(self) -> None:
        # Header
        header = ttk.Frame(self, style="Wizard.TFrame")
        header.pack(fill=tk.X, padx=40, pady=(20, 10))

        ttk.Label(
            header,
            text="Create New Container",
            style="WizardHeader.TLabel",
        ).pack(anchor=tk.W)

        ttk.Label(
            header,
            text="Configure your new LXC container step by step",
            style="Wizard.SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(5, 0))

        # Step indicator
        self.step_indicator = ttk.Label(
            header,
            text="Step 1 of 4",
            style="Wizard.TLabel",
        )
        self.step_indicator.pack(anchor=tk.W, pady=(10, 0))

        # Steps container
        steps_container = ttk.Frame(self, style="Wizard.TFrame")
        steps_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 20))

        self.steps = [
            self._build_basic_info_step(),
            self._build_template_step(),
            self._build_resources_step(),
            self._build_network_step(),
        ]

        # Navigation buttons
        nav_frame = ttk.Frame(self, style="Wizard.TFrame")
        nav_frame.pack(fill=tk.X, padx=40, pady=(0, 20))

        self.back_button = ttk.Button(
            nav_frame,
            text="Back",
            command=self._previous_step,
            style="Wizard.Secondary.TButton",
        )
        self.back_button.pack(side=tk.LEFT)

        self.next_button = ttk.Button(
            nav_frame,
            text="Next",
            command=self._next_step,
            style="Wizard.TButton",
        )
        self.next_button.pack(side=tk.RIGHT)

    def _build_basic_info_step(self) -> ttk.Frame:
        frame = ttk.Frame(self, style="Wizard.Card.TFrame")

        ttk.Label(
            frame,
            text="Basic Information",
            style="WizardHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 15))

        self._add_labeled_entry(frame, "Container ID (optional):", self.ctid_var)
        self._add_labeled_entry(frame, "Hostname:", self.hostname_var)
        self._add_labeled_entry(frame, "Root Password:", self.password_var, show="*")
        self._add_labeled_entry(frame, "Confirm Password:", self.password_confirm_var, show="*")

        # Node selection
        ttk.Label(frame, text="Node:", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.node_combo = ttk.Combobox(
            frame,
            textvariable=self.node_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.node_combo.pack(fill=tk.X, pady=(0, 5))
        self.node_combo.bind("<<ComboboxSelected>>", self._on_node_selected)

        return frame

    def _build_template_step(self) -> ttk.Frame:
        frame = ttk.Frame(self, style="Wizard.Card.TFrame")

        ttk.Label(
            frame,
            text="Template & Storage",
            style="WizardHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 15))

        # Template selection
        ttk.Label(frame, text="Template:", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.template_combo = ttk.Combobox(
            frame,
            textvariable=self.template_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.template_combo.pack(fill=tk.X, pady=(0, 15))

        # Storage selection
        ttk.Label(frame, text="Storage:", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
        self.storage_combo = ttk.Combobox(
            frame,
            textvariable=self.storage_var,
            state="readonly",
            style="Wizard.TCombobox",
        )
        self.storage_combo.pack(fill=tk.X, pady=(0, 15))

        # Disk size
        self._add_labeled_entry(frame, "Disk Size (GB):", self.disk_size_var)

        return frame

    def _build_resources_step(self) -> ttk.Frame:
        frame = ttk.Frame(self, style="Wizard.Card.TFrame")

        ttk.Label(
            frame,
            text="Resources",
            style="WizardHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 15))

        self._add_labeled_entry(frame, "CPU Cores:", self.cpu_cores_var)
        self._add_labeled_entry(frame, "Memory (MB):", self.memory_var)

        return frame

    def _build_network_step(self) -> ttk.Frame:
        frame = ttk.Frame(self, style="Wizard.Card.TFrame")

        ttk.Label(
            frame,
            text="Network",
            style="WizardHeader.TLabel",
        ).pack(anchor=tk.W, pady=(0, 15))

        # Bridge selection
        ttk.Label(frame, text="Network Bridge:", style="Wizard.TLabel").pack(anchor=tk.W, pady=(5, 2))
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
        """Load nodes, storages, templates, and networks from Proxmox."""
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
                error_message = str(exc)

                def show_error() -> None:
                    _styled_error(
                        self,
                        "Connection Error",
                        f"Unable to connect to Proxmox server:\n{error_message}",
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
        """Load storage and template data for the selected node."""
        if not self.client:
            return

        def worker() -> None:
            try:
                # Load storages
                storages = self.client.get_node_storage(node)
                self.storages = storages
                container_storages: list[str] = []
                template_options: list[str] = []
                template_map: dict[str, str] = {}

                for storage in storages:
                    storage_name = storage.get("storage")
                    if not storage_name:
                        continue
                    content_types = storage.get("content", "") or ""

                    # Storages that support container rootfs
                    if "rootdir" in content_types or storage.get("type") in ("dir", "zfspool", "rbd"):
                        container_storages.append(storage_name)

                    # Storages that contain templates
                    if "vztmpl" in content_types:
                        try:
                            templates = self.client.get_container_templates(node, storage_name)
                            for item in templates:
                                volid = item.get("volid")
                                if not volid:
                                    continue
                                template_name = volid.split("/")[-1]
                                display = f"{template_name} ({storage_name})"
                                template_options.append(display)
                                template_map[display] = volid
                        except Exception:
                            continue

                def update_ui() -> None:
                    if container_storages:
                        self.storage_combo["values"] = container_storages
                        if not self.storage_var.get():
                            self.storage_var.set(container_storages[0])

                    if template_options:
                        self.template_choices = template_map
                        self.template_combo["values"] = template_options
                        if not self.template_var.get():
                            self.template_var.set(template_options[0])
                    else:
                        self.template_choices = {}
                        self.template_combo["values"] = []

                self.after(0, update_ui)
            except Exception:
                pass  # Silently fail for storage/template loading

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
            self._create_container()
        else:
            self._show_step(self.current_step + 1)

    def _previous_step(self) -> None:
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    def _validate_current_step(self) -> bool:
        if self.current_step == 0:
            hostname = self.hostname_var.get().strip()
            password = self.password_var.get().strip()
            password_confirm = self.password_confirm_var.get().strip()
            node = self.node_var.get().strip()

            if not hostname:
                _styled_error(self, "Missing information", "Hostname is required.")
                return False

            if not password:
                _styled_error(self, "Missing information", "Root password is required.")
                return False

            if password != password_confirm:
                _styled_error(self, "Password mismatch", "Passwords do not match.")
                return False

            if not node:
                _styled_error(self, "Missing information", "Please select a node.")
                return False

        elif self.current_step == 1:
            template = self.template_var.get().strip()
            storage = self.storage_var.get().strip()
            
            if not template:
                _styled_error(self, "Missing information", "Please select a template.")
                return False

            if not storage:
                _styled_error(self, "Missing information", "Please select a storage.")
                return False

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

        elif self.current_step == 2:
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

        elif self.current_step == 3:
            bridge = self.bridge_var.get().strip()
            if not bridge:
                _styled_error(self, "Missing information", "Please select a network bridge.")
                return False

        return True

    def _create_container(self) -> None:
        """Create the container with the configured settings."""
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
                
                # Get or generate Container ID
                ctid_str = self.ctid_var.get().strip()
                if ctid_str:
                    try:
                        ctid = int(ctid_str)
                    except ValueError:
                        def show_error() -> None:
                            _styled_error(self, "Invalid Container ID", "Container ID must be a number.")
                        self.after(0, show_error)
                        return
                else:
                    ctid = client.get_next_vmid()

                node = self.node_var.get().strip()
                hostname = self.hostname_var.get().strip()
                password = self.password_var.get().strip()
                template_display = self.template_var.get().strip()
                storage = self.storage_var.get().strip()
                disk_size_gb = int(self.disk_size_var.get().strip())
                cpu_cores = int(self.cpu_cores_var.get().strip())
                memory_mb = int(self.memory_var.get().strip())
                bridge = self.bridge_var.get().strip()

                template_volid = self.template_choices.get(template_display)
                if not template_volid:
                    def show_error() -> None:
                        _styled_error(
                            self,
                            "Template Error",
                            "Please select a valid template. Templates that are unavailable will need to be downloaded via the Proxmox web interface.",
                        )
                    self.after(0, show_error)
                    return

                # Build container config
                config: dict[str, Any] = {
                    "hostname": hostname,
                    "password": password,
                    "ostype": "debian",  # Default, can be detected from template
                    "cores": cpu_cores,
                    "memory": memory_mb,
                    "swap": 0,
                    "unprivileged": 1,
                    "net0": f"name=eth0,bridge={bridge},ip=dhcp,type=veth",
                    "rootfs": f"{storage}:{disk_size_gb}",
                    "ostemplate": template_volid,
                    "storage": storage,
                    "onboot": 0,
                    "start": 0,
                }

                # Create container
                result = client.create_container(node, ctid, config)

                def show_success() -> None:
                    _styled_info(
                        self,
                        "Container Created",
                        f"Container '{hostname}' (ID: {ctid}) has been created successfully!\n\nYou can now start it from the Manage Containers view.",
                    )
                    if self.on_complete:
                        self.on_complete({"ctid": ctid, "hostname": hostname, "node": node})
                    self._reset_form()

                self.after(0, show_success)
            except ProxmoxAPIError as exc:
                error_message = str(exc)

                def show_error() -> None:
                    _styled_error(self, "Creation Failed", f"Failed to create container:\n{error_message}")
                self.after(0, show_error)
            except Exception as exc:
                error_message = str(exc)

                def show_error() -> None:
                    _styled_error(self, "Unexpected Error", f"An error occurred:\n{error_message}")
                self.after(0, show_error)
            finally:
                if client:
                    client.close()

        threading.Thread(target=worker, daemon=True).start()

    def _reset_form(self) -> None:
        """Reset the form to initial state."""
        self.ctid_var.set("")
        self.hostname_var.set("")
        self.password_var.set("")
        self.password_confirm_var.set("")
        self.disk_size_var.set("8")
        self.cpu_cores_var.set("1")
        self.memory_var.set("512")
        self.template_var.set("")
        self.storage_var.set("")
        self.bridge_var.set("")
        self._show_step(0)

