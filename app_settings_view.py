import tkinter as tk

from preferences import get_preference, set_preference
from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_MEDIUM, PROXMOX_ORANGE


def build_view(parent: tk.Widget) -> tk.Frame:
    root = parent.winfo_toplevel()
    frame = tk.Frame(parent, bg=PROXMOX_DARK)

    title = tk.Label(
        frame,
        text="App Settings",
        font=("Segoe UI", 24, "bold"),
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    title.pack(anchor=tk.W, pady=(40, 4), padx=40)

    description = tk.Label(
        frame,
        text="Manage application preferences such as display mode.",
        font=("Segoe UI", 12),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
    )
    description.pack(anchor=tk.W, padx=40, pady=(0, 20))

    app_state = getattr(root, "app_state", None)
    account = app_state.get("account") if isinstance(app_state, dict) else None
    if not account:
        tk.Label(
            frame,
            text="No account is active. Please complete the setup wizard first.",
            font=("Segoe UI", 12),
            fg="#ffb3a7",
            bg=PROXMOX_DARK,
            justify=tk.LEFT,
            wraplength=700,
        ).pack(anchor=tk.W, padx=40, pady=(10, 0))
        return frame

    mode_var = tk.StringVar(value=get_preference(root, "window_mode", "windowed"))
    status_var = tk.StringVar(value="")

    card = tk.Frame(frame, bg=PROXMOX_MEDIUM)
    card.pack(fill=tk.X, padx=40, pady=(0, 20))

    tk.Label(
        card,
        text="Display Mode",
        font=("Segoe UI", 16, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(anchor=tk.W, pady=(20, 4), padx=20)

    tk.Label(
        card,
        text="Choose whether the application runs in a resizable window or full screen.",
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        wraplength=760,
        justify=tk.LEFT,
    ).pack(anchor=tk.W, padx=20, pady=(0, 10))

    options = tk.Frame(card, bg=PROXMOX_MEDIUM)
    options.pack(anchor=tk.W, padx=20, pady=(5, 15))

    def create_mode_option(label: str, value: str, info: str) -> None:
        option = tk.Frame(options, bg=PROXMOX_MEDIUM)
        option.pack(anchor=tk.W, pady=4, fill=tk.X)
        tk.Radiobutton(
            option,
            text=label,
            value=value,
            variable=mode_var,
            font=("Segoe UI", 12, "bold"),
            bg=PROXMOX_MEDIUM,
            fg=PROXMOX_LIGHT,
            activebackground=PROXMOX_MEDIUM,
            activeforeground=PROXMOX_LIGHT,
            selectcolor=PROXMOX_DARK,
            anchor="w",
        ).pack(anchor=tk.W)
        tk.Label(
            option,
            text=info,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
            wraplength=660,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=(28, 0))

    create_mode_option("Windowed", "windowed", "Run Proxmox-LDC in a standard resizable window.")
    create_mode_option("Full Screen", "fullscreen", "Fill the entire display, hiding the system window chrome.")

    def apply_mode() -> None:
        mode = "fullscreen" if mode_var.get() == "fullscreen" else "windowed"
        apply_fn = getattr(root, "apply_window_mode", None)
        if callable(apply_fn):
            apply_fn(mode)
        set_preference(root, "window_mode", mode)
        status_var.set(f"Window mode set to {'Full Screen' if mode == 'fullscreen' else 'Windowed'}.")

    footer = tk.Frame(frame, bg=PROXMOX_DARK)
    footer.pack(fill=tk.X, padx=40)

    tk.Button(
        footer,
        text="Apply",
        command=apply_mode,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=10,
    ).pack(side=tk.LEFT)

    tk.Label(
        footer,
        textvariable=status_var,
        font=("Segoe UI", 10),
        fg="#7ddc88",
        bg=PROXMOX_DARK,
    ).pack(side=tk.LEFT, padx=(15, 0))

    return frame

