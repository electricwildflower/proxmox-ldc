from __future__ import annotations

import hashlib
import socket
import ssl
from urllib.parse import urlparse

import tkinter as tk

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_ORANGE
from typing import Any, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover
    x509 = None  # type: ignore[assignment]
    default_backend = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]


def normalize_server_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("Server URL is required.")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def _host_port_from_url(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    if parsed.port:
        port = parsed.port
    else:
        if parsed.scheme == "http":
            port = 80
        else:
            port = 8006
    return hostname, port


def fetch_server_certificate(url: str, *, timeout: float = 10.0) -> tuple[str, str, str]:
    normalized = normalize_server_url(url)
    hostname, port = _host_port_from_url(normalized)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            der_cert = secure_sock.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(der_cert).hexdigest().upper()
            chain_pems: list[str] = []
            if hasattr(secure_sock, "getpeercertchain"):
                try:
                    chain = secure_sock.getpeercertchain()
                    for cert in chain:
                        chain_pems.append(ssl.DER_cert_to_PEM_cert(cert))
                except Exception:
                    chain_pems.append(ssl.DER_cert_to_PEM_cert(der_cert))
            else:
                chain_pems.append(ssl.DER_cert_to_PEM_cert(der_cert))

    pem_bundle = "".join(chain_pems)
    return normalized, pem_bundle, fingerprint


def prompt_trust_dialog(parent: tk.Widget, host: str, fingerprint: str) -> bool:
    dialog = tk.Toplevel(parent)
    dialog.title("Trust this server?")
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()

    width, height = 520, 260
    root = parent.winfo_toplevel()
    root.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() // 2) - (width // 2)
    y = root.winfo_rooty() + (root.winfo_height() // 2) - (height // 2)
    dialog.geometry(f"{width}x{height}+{x}+{y}")

    tk.Label(
        dialog,
        text="Trust this server?",
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(anchor=tk.W, padx=30, pady=(25, 5))

    body = tk.Label(
        dialog,
        text=(
            "You're about to trust the TLS certificate presented by:\n"
            f"{host}\n\n"
            "Fingerprint (SHA-256):\n"
            f"{fingerprint}"
        ),
        font=("Segoe UI", 11),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
        wraplength=460,
    )
    body.pack(anchor=tk.W, padx=30, pady=(0, 15))

    response = {"value": False}

    def choose(value: bool) -> None:
        response["value"] = value
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))

    tk.Button(
        buttons,
        text="Reject",
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
        text="Trust Server",
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


def _format_dt(dt: Any) -> str:
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(dt)


def load_certificate_details(pem_path: str) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if not x509:
        details["error"] = "cryptography module not available"
        return details
    pem_data = open(pem_path, "rb").read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    details["subject"] = cert.subject.rfc4514_string()
    details["issuer"] = cert.issuer.rfc4514_string()
    details["not_before"] = _format_dt(cert.not_valid_before)
    details["not_after"] = _format_dt(cert.not_valid_after)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        details["sans"] = ", ".join(san.get_values_for_type(x509.DNSName))
    except Exception:
        details["sans"] = ""
    # Compute sha256 fingerprint from DER
    if serialization is not None:
        der = cert.public_bytes(encoding=serialization.Encoding.DER)
    else:
        der = pem_data
    try:
        # cryptography exposes fingerprint method
        fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        details["fingerprint"] = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
    except Exception:
        sha = hashlib.sha256(der).hexdigest().upper()
        details["fingerprint"] = ":".join(sha[i:i+2] for i in range(0, len(sha), 2))
    return details


def show_certificate_details_dialog(parent: tk.Widget, pem_path: str) -> None:
    dialog = tk.Toplevel(parent)
    dialog.title("Trusted Certificate")
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()

    width, height = 640, 360
    root = parent.winfo_toplevel()
    root.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() // 2) - (width // 2)
    y = root.winfo_rooty() + (root.winfo_height() // 2) - (height // 2)
    dialog.geometry(f"{width}x{height}+{x}+{y}")

    tk.Label(
        dialog,
        text="Trusted Certificate Details",
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    ).pack(anchor=tk.W, padx=30, pady=(25, 10))

    body = tk.Frame(dialog, bg=PROXMOX_DARK)
    body.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 10))

    details = load_certificate_details(pem_path)
    lines = [
        ("Subject", details.get("subject", "")),
        ("Issuer", details.get("issuer", "")),
        ("Valid From", details.get("not_before", "")),
        ("Valid To", details.get("not_after", "")),
        ("SANs", details.get("sans", "")),
        ("SHA-256", details.get("fingerprint", "")),
        ("Path", pem_path),
    ]

    for label, value in lines:
        row = tk.Frame(body, bg=PROXMOX_DARK)
        row.pack(fill=tk.X, pady=4)
        tk.Label(
            row,
            text=f"{label}:",
            font=("Segoe UI", 11, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            width=12,
            anchor="w",
        ).pack(side=tk.LEFT)
        tk.Label(
            row,
            text=value or "",
            font=("Segoe UI", 11),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            wraplength=520,
            justify=tk.LEFT,
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    buttons = tk.Frame(dialog, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))

    def close() -> None:
        dialog.destroy()

    tk.Button(
        buttons,
        text="Close",
        command=close,
        font=("Segoe UI", 11),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.RIGHT)

