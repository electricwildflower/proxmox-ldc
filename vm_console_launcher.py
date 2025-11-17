from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox
from typing import Any, Callable
from urllib.parse import urlparse

from proxmox_client import ProxmoxAPIError, ProxmoxClient, ProxmoxSummary

StatusCallback = Callable[[str], None] | None


def launch_vm_console(
    root: tk.Misc,
    vm_obj: dict[str, Any],
    summary_obj: ProxmoxSummary | dict[str, Any] | None,
    *,
    status_callback: StatusCallback = None,
) -> None:
    """Fetch a SPICE config from Proxmox and open it in a separate viewer window."""

    def update_status(message: str) -> None:
        if status_callback:
            try:
                status_callback(message)
            except Exception:
                pass

    account = getattr(root, "app_state", {}).get("account") if hasattr(root, "app_state") else None
    if not account:
        messagebox.showerror("Console unavailable", "Account information is missing.", parent=root)
        return

    proxmox_cfg = account.get("proxmox", {})
    host = proxmox_cfg.get("host")
    username = proxmox_cfg.get("username")
    password = proxmox_cfg.get("password")
    verify_ssl = proxmox_cfg.get("verify_ssl", False)
    trusted_cert = proxmox_cfg.get("trusted_cert")
    trusted_fp = proxmox_cfg.get("trusted_cert_fingerprint")

    if not all([host, username, password]):
        messagebox.showerror(
            "Console unavailable",
            "Connection details are incomplete. Please update your account configuration.",
            parent=root,
        )
        return

    node_name = _resolve_node_name(summary_obj, vm_obj)
    if not node_name:
        messagebox.showerror(
            "Console unavailable",
            "Unable to determine the node that hosts this VM.",
            parent=root,
        )
        return

    vmid = vm_obj.get("vmid")
    if vmid is None:
        messagebox.showerror("Console unavailable", "VM ID is missing.", parent=root)
        return

    viewer_cmd = _find_viewer_command()
    if not viewer_cmd:
        messagebox.showerror(
            "Viewer required",
            "No SPICE viewer was found.\n\nInstall the 'virt-viewer' package (provides remote-viewer) "
            "and try again:\n  sudo apt install virt-viewer",
            parent=root,
        )
        update_status("Console viewer is not installed.")
        return

    vm_name = vm_obj.get("name") or f"VM {vmid}"
    update_status(f"Requesting console for {vm_name}...")

    def worker() -> None:
        client: ProxmoxClient | None = None
        spice_config: str | None = None
        vnc_info: dict[str, Any] | None = None
        error_message: str | None = None
        try:
            client = ProxmoxClient(
                host=host,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
                trusted_cert=trusted_cert,
                trusted_fingerprint=trusted_fp,
            )
            try:
                spice_config = client.get_spice_config(node_name, vmid)
            except ProxmoxAPIError as exc:
                if "no spice port" in str(exc).lower():
                    update_status("SPICE display not enabled; falling back to VNC.")
                    vnc_info = client.get_vnc_proxy(node_name, vmid)
                else:
                    raise
        except ProxmoxAPIError as exc:
            error_message = f"API error: {exc}"
        except Exception as exc:
            error_message = f"Failed to fetch console details: {exc}"
        finally:
            if client:
                client.close()

        def finalize() -> None:
            if error_message:
                messagebox.showerror("Console error", error_message, parent=root)
                update_status(f"Unable to open console for {vm_name}.")
                return
            if spice_config:
                _spawn_spice_viewer(root, vm_name, spice_config, viewer_cmd, update_status)
                return
            if vnc_info:
                _spawn_vnc_viewer(
                    root,
                    vm_name,
                    proxmox_cfg.get("host") or "",
                    vnc_info,
                    viewer_cmd,
                    update_status,
                )
                return
            messagebox.showerror("Console error", "Received empty console configuration.", parent=root)
            update_status(f"Unable to open console for {vm_name}.")

        try:
            root.after(0, finalize)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()


def _resolve_node_name(summary_obj: ProxmoxSummary | dict[str, Any] | None, vm_obj: dict[str, Any]) -> str | None:
    if isinstance(summary_obj, ProxmoxSummary):
        node_name = summary_obj.node_name
    elif isinstance(summary_obj, dict):
        node_name = summary_obj.get("node_name") or summary_obj.get("node")
    else:
        node_name = None
    return node_name or vm_obj.get("node")


def _find_viewer_command() -> str | None:
    for candidate in ("remote-viewer", "virt-viewer"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _spawn_spice_viewer(
    root: tk.Misc,
    vm_name: str,
    spice_config: str,
    viewer_cmd: str,
    update_status: Callable[[str], None],
) -> None:
    _launch_viewer_from_config(root, vm_name, spice_config, viewer_cmd, update_status)


def _launch_viewer_from_config(
    root: tk.Misc,
    vm_name: str,
    config_text: str,
    viewer_cmd: str,
    update_status: Callable[[str], None],
) -> None:
    tmp_file: tempfile.NamedTemporaryFile[str] | None = None
    try:
        tmp_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".vv")
        tmp_file.write(config_text)
        tmp_file.flush()
        tmp_path = tmp_file.name
    except Exception as exc:
        messagebox.showerror("Console error", f"Failed to prepare viewer file: {exc}", parent=root)
        update_status("Unable to open console window.")
        return
    finally:
        try:
            if tmp_file:
                tmp_file.close()
        except Exception:
            pass

    title = f"{vm_name} – Proxmox"
    args = [viewer_cmd, "--title", title, tmp_path]

    try:
        subprocess.Popen(args)
        update_status(f"Console opened for {vm_name} in a new window.")
    except FileNotFoundError:
        messagebox.showerror(
            "Viewer not found",
            f"Failed to launch '{viewer_cmd}'. Ensure virt-viewer is installed and accessible.",
            parent=root,
        )
        update_status("Unable to open console window.")
        _cleanup_tempfile(tmp_path)
        return
    except Exception as exc:
        messagebox.showerror("Viewer launch failed", f"Unable to start the viewer:\n{exc}", parent=root)
        update_status("Unable to open console window.")
        _cleanup_tempfile(tmp_path)
        return

    # Clean up the temp file after the viewer has had time to read it.
    try:
        root.after(60000, lambda: _cleanup_tempfile(tmp_path))
    except Exception:
        _cleanup_tempfile(tmp_path)


def _spawn_vnc_viewer(
    root: tk.Misc,
    vm_name: str,
    host_url: str,
    vnc_info: dict[str, Any],
    viewer_cmd: str,
    update_status: Callable[[str], None],
) -> None:
    hostname = _extract_hostname(host_url)
    port = vnc_info.get("port")
    password = vnc_info.get("password") or vnc_info.get("ticket") or vnc_info.get("vncticket")

    if not hostname or not port:
        messagebox.showerror(
            "Console error",
            "Proxmox did not return the information required to open the VNC console.",
            parent=root,
        )
        update_status("Unable to open VNC console window.")
        return

    lines = [
        "[virt-viewer]",
        "type=vnc",
        f"host={hostname}",
        f"port={port}",
        f"title={vm_name} – Proxmox",
        "delete-this-file=1",
    ]
    if password:
        lines.append(f"password={password}")
    if vnc_info.get("tlsport"):
        lines.append(f"tls-port={vnc_info['tlsport']}")
    config = "\n".join(lines) + "\n"

    _launch_viewer_from_config(root, vm_name, config, viewer_cmd, update_status)


def _extract_hostname(host: str) -> str:
    parsed = urlparse(host)
    if parsed.hostname:
        return parsed.hostname
    return host.replace("https://", "").replace("http://", "").split("/")[0]


def _cleanup_tempfile(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

