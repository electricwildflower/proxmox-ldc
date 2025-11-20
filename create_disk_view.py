import tkinter as tk

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_ORANGE


def build_view(parent: tk.Widget) -> tk.Frame:
    frame = tk.Frame(parent, bg=PROXMOX_DARK)

    title = tk.Label(
        frame,
        text="Create VM Disk",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 10), padx=40)

    description = tk.Label(
        frame,
        text="Placeholder UI for creating new VM disks.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
    )
    description.pack(anchor=tk.W, padx=40)

    return frame

