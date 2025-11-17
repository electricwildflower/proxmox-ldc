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
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE

StatusCallback = Callable[[str], None] | None
DISPLAY_ONLY_WARNING = (
    "Proxmox reports that '{vm}' is attached to a local/physical display, so a remote console "
    "is not available. Detach the physical display (or enable a SPICE/VNC display) if you "
    "need to open it inside the app."
)


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

    from main import get_active_proxmox_config
    proxmox_cfg = get_active_proxmox_config(account) or {}
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
        display_warning: str | None = None
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
                vm_config = client.get_vm_config(node_name, vmid)
                if _vm_config_has_external_display(vm_config):
                    display_warning = DISPLAY_ONLY_WARNING.format(vm=vm_obj.get("name") or f"VM {vmid}")
            except ProxmoxAPIError:
                vm_config = None
            spice_error_text: str | None = None
            try:
                spice_config = client.get_spice_config(node_name, vmid)
            except ProxmoxAPIError as exc:
                spice_error_text = str(exc)
            if spice_config is None:
                try:
                    if spice_error_text:
                        update_status("SPICE console not available; attempting VNC.")
                    vnc_info = client.get_vnc_proxy(node_name, vmid)
                except ProxmoxAPIError as exc:
                    combined_errors = f"{spice_error_text or ''}\n{exc}"
                    if _is_display_only_error(combined_errors):
                        display_warning = DISPLAY_ONLY_WARNING.format(vm=vm_obj.get("name") or f"VM {vmid}")
                    else:
                        error_message = f"API error: {exc}"
        except ProxmoxAPIError as exc:
            error_message = f"API error: {exc}"
        except Exception as exc:
            error_message = f"Failed to fetch console details: {exc}"
        finally:
            if client:
                client.close()

        def finalize() -> None:
            if display_warning:
                _show_console_warning_dialog(root, display_warning)
                update_status("Console not available for this VM.")
                return
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


def _find_vnc_viewer_command() -> str | None:
    """Find an alternative VNC viewer that might handle certificates better."""
    for candidate in ("vncviewer", "tigervnc", "xtightvncviewer", "vnc"):
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
    if not _spice_config_supports_remote(spice_config):
        _show_console_warning_dialog(
            root,
            DISPLAY_ONLY_WARNING.format(vm=vm_name),
        )
        update_status("Console not available for this VM.")
        return
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
    
    # For containers with TLS, add options to keep window open and visible
    # Check if this is a container connection by looking at the config
    is_tls_connection = "tls-port" in config_text.lower() or "type=vnc" in config_text.lower()
    
    if is_tls_connection:
        # Try to add options that might help with certificate dialogs
        # Some versions of remote-viewer support these
        try:
            # Try to ensure the window stays open and is visible
            import platform
            if platform.system() == "Linux":
                # On Linux, try to use wmctrl or xdotool to bring window to front
                # But first, just launch and hope the dialog is visible
                pass
        except Exception:
            pass

    try:
        # For TLS/VNC connections, we need to keep the window open and visible
        # so the certificate dialog can be seen and interacted with
        # Don't wait for the process - let it run independently
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,  # Capture stderr to check for errors
            start_new_session=True,  # Run in new session so it doesn't close when parent closes
        )
        
        # Store process reference to prevent garbage collection
        if not hasattr(root, "_console_processes"):
            root._console_processes = []  # type: ignore[attr-defined]
        root._console_processes.append(proc)  # type: ignore[attr-defined]
        
        # For TLS connections (containers), ensure the window stays open and is visible
        if is_tls_connection:
            def ensure_window_visible() -> None:
                """Try to bring the remote-viewer window to front and keep it visible."""
                try:
                    import shutil
                    import subprocess as sp
                    import time
                    
                    # Wait a bit for the window to appear
                    time.sleep(0.3)
                    
                    # Try multiple methods to bring window to front
                    if shutil.which("wmctrl"):
                        # Find window by title and activate it
                        sp.Popen(["wmctrl", "-a", title], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                        # Also try to find by class name
                        sp.Popen(["wmctrl", "-a", "remote-viewer"], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                    elif shutil.which("xdotool"):
                        # Search for window by name and activate
                        sp.Popen(["xdotool", "search", "--name", title, "windowactivate", "--sync"], 
                                stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                        # Also try searching for remote-viewer
                        sp.Popen(["xdotool", "search", "--class", "remote-viewer", "windowactivate"], 
                                stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                except Exception:
                    pass
            
            # Try to bring window to front multiple times to ensure it's visible
            try:
                import threading
                # Run in a separate thread so it doesn't block
                threading.Thread(target=ensure_window_visible, daemon=True).start()
                # Also try via root.after for GUI thread
                root.after(300, ensure_window_visible)
                root.after(800, ensure_window_visible)
                root.after(1500, ensure_window_visible)
            except Exception:
                pass
        
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
    *,
    is_container: bool = False,
) -> None:
    hostname = _extract_hostname(host_url)
    port = vnc_info.get("port")
    tls_port = vnc_info.get("tlsport")
    password = vnc_info.get("password") or vnc_info.get("ticket") or vnc_info.get("vncticket")

    # Prefer non-TLS port to avoid certificate trust issues
    # Only use TLS port if regular port is not available
    actual_port = port if port else tls_port
    using_tls_only = not port and tls_port  # Only TLS port available

    if not hostname or not actual_port:
        _show_console_warning_dialog(
            root,
            DISPLAY_ONLY_WARNING.format(vm=vm_name),
        )
        update_status("Console not available for this VM.")
        return

    # For containers with only TLS port, try alternative VNC viewer that might handle certificates better
    if is_container and using_tls_only:
        alt_viewer = _find_vnc_viewer_command()
        if alt_viewer:
            # Try using alternative VNC viewer with certificate options
            try:
                import subprocess
                # Some VNC viewers support -Shared, -ViewOnly, etc., but certificate handling varies
                # Try connecting without TLS first (might work if server accepts it)
                args = [alt_viewer, f"{hostname}:{actual_port}"]
                if password:
                    # Some viewers support password via stdin or file
                    # For now, user will need to enter password manually
                    pass
                proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                update_status(f"Opening console for {vm_name} with alternative viewer. Enter password if prompted.")
                return
            except Exception:
                pass  # Fall back to remote-viewer if alternative fails

    # Use remote-viewer with .vv file (standard approach)
    lines = [
        "[virt-viewer]",
        "type=vnc",
        f"host={hostname}",
        f"port={actual_port}",
        f"title={vm_name} – Proxmox",
        "delete-this-file=1",
    ]
    if password:
        lines.append(f"password={password}")
    # Don't add tls-port - let remote-viewer try non-TLS first
    # If server requires TLS, user will need to accept certificate manually
    config = "\n".join(lines) + "\n"

    # For containers with TLS-only, show a clear message about the limitation
    if is_container and using_tls_only:
        # Show a warning dialog BEFORE trying to open, explaining the limitation
        try:
            dialog = tk.Toplevel(root)
            dialog.title("Container Console Limitation")
            dialog.configure(bg=PROXMOX_DARK)
            dialog.transient(root)
            dialog.grab_set()
            dialog.resizable(False, False)
            
            try:
                dialog.attributes("-topmost", True)
            except Exception:
                pass

            tk.Label(
                dialog,
                text="Container Console Access Limitation",
                font=("Segoe UI", 14, "bold"),
                fg=PROXMOX_ORANGE,
                bg=PROXMOX_DARK,
            ).pack(padx=24, pady=(20, 6))

            message = (
                f"Container '{vm_name}' requires a secure TLS VNC connection.\n\n"
                "Unfortunately, remote-viewer does not support interactive\n"
                "certificate acceptance for VNC TLS connections, and will fail\n"
                "with a certificate error.\n\n"
                "Alternative options:\n"
                "• Use SSH to access the container console\n"
                "• Access the container via the Proxmox web interface\n"
                "• Configure Proxmox to provide non-TLS VNC ports\n\n"
                "Would you like to try opening the console anyway?\n"
                "(It will likely show a certificate error)"
            )
            
            tk.Label(
                dialog,
                text=message,
                font=("Segoe UI", 11),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
                wraplength=500,
                justify=tk.LEFT,
            ).pack(padx=24, pady=(0, 16))

            buttons_frame = tk.Frame(dialog, bg=PROXMOX_DARK)
            buttons_frame.pack(padx=24, pady=(0, 20))
            
            result = {"continue": False}
            
            def cancel() -> None:
                dialog.destroy()
            
            def continue_anyway() -> None:
                result["continue"] = True
                dialog.destroy()
            
            tk.Button(
                buttons_frame,
                text="Cancel",
                command=cancel,
                font=("Segoe UI", 11),
                bg="#2f3640",
                fg=PROXMOX_LIGHT,
                activebackground="#3a414d",
                activeforeground=PROXMOX_LIGHT,
                bd=0,
                padx=18,
                pady=8,
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            tk.Button(
                buttons_frame,
                text="Try Anyway",
                command=continue_anyway,
                font=("Segoe UI", 11, "bold"),
                bg=PROXMOX_ORANGE,
                fg="white",
                activebackground="#ff8126",
                activeforeground="white",
                bd=0,
                padx=18,
                pady=8,
            ).pack(side=tk.LEFT)
            
            dialog.wait_window()
            
            if not result["continue"]:
                update_status("Container console opening cancelled.")
                return
        except Exception:
            pass  # If dialog fails, continue anyway

    _launch_viewer_from_config(root, vm_name, config, viewer_cmd, update_status)


def _extract_hostname(host: str) -> str:
    parsed = urlparse(host)
    if parsed.hostname:
        return parsed.hostname
    return host.replace("https://", "").replace("http://", "").split("/")[0]


def _is_display_only_error(message: str) -> bool:
    text = (message or "").lower()
    if not text:
        return False
    if "no spice port" in text:
        return False
    keywords = [
        "display",
        "gpu",
        "passthrough",
        "hostpci",
        "no vnc",
        "no console",
        "console is disabled",
        "no spice proxy",
    ]
    return any(keyword in text for keyword in keywords)


def _vm_config_has_external_display(vm_config: dict[str, Any] | None) -> bool:
    if not vm_config:
        return False
    vga_value = str(vm_config.get("vga") or "").lower()
    if not vga_value:
        return False
    if vga_value == "none":
        return True
    if "type=none" in vga_value:
        return True
    if vga_value.startswith("serial"):
        return True
    if vga_value.startswith("spice"):
        return False
    return False


def _spice_config_supports_remote(config: str) -> bool:
    has_network = False
    for raw_line in config.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in {"host", "proxy"}:
            has_network = True
            if value.startswith("/") or value.startswith("unix"):
                return False
    return has_network


def _show_console_warning_dialog(root: tk.Misc, message: str) -> None:
    try:
        dialog = tk.Toplevel(root)
        dialog.title("Console unavailable")
        dialog.configure(bg=PROXMOX_DARK)
        dialog.transient(root)
        dialog.grab_set()
        dialog.resizable(False, False)
        try:
            dialog.attributes("-topmost", True)
        except Exception:
            pass

        tk.Label(
            dialog,
            text="Console unavailable",
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
            wraplength=420,
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
    except Exception:
        messagebox.showwarning("Console unavailable", message, parent=root)


def _cleanup_tempfile(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

