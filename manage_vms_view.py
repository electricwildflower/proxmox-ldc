from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from typing import Any

from proxmox_client import ProxmoxAPIError, ProxmoxClient
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE
from vm_console_launcher import launch_vm_console


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
    sort_var = tk.StringVar(value=sort_options[0][0])

    tk.Label(
        search_frame,
        text="Order by:",
        font=("Segoe UI", 11, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(10, 6))

    sort_dropdown = tk.OptionMenu(
        search_frame,
        sort_var,
        *label_to_key.keys(),
        command=lambda _: render_vm_rows(),
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

        proxmox_cfg = account.get("proxmox", {})
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
                    client.start_vm(node_name, vmid)
                    message = f"{name} is starting."
                elif action == "stop":
                    client.stop_vm(node_name, vmid)
                    message = f"{name} is stopping."
                else:
                    client.reboot_vm(node_name, vmid)
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
                refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
                if callable(refresh_cb):
                    refresh_cb(mode="full", force=True)
                root.after(1500, refresh_data)

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
                    proxmox_cfg = account.get("proxmox", {})
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
                        client.start_vm(node_name, vmid)
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

        action_button("View", lambda vm=vm: open_console(vm), True)

    def refresh_data(force: bool = False) -> None:
        app_state = getattr(root, "app_state", None)
        summary = None
        if isinstance(app_state, dict):
            dashboard_data = app_state.get("dashboard_data") or {}
            summary = dashboard_data.get("summary")

        if summary is None:
            if force:
                status_var.set("Requesting latest VM data...")
                refresh_cb = getattr(root, "trigger_dashboard_refresh", None)
                if callable(refresh_cb):
                    refresh_cb(mode="full", force=True)
                    root.after(1500, refresh_data)
                else:
                    status_var.set("Unable to trigger a dashboard refresh.")
            else:
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

    search_var.trace_add("write", lambda *_: render_vm_rows())
    refresh_data()
    search_entry.focus_set()

    return frame

