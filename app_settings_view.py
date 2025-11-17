import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

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
        text="Manage application preferences and configuration settings.",
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

    card = tk.Frame(frame, bg=PROXMOX_MEDIUM)
    card.pack(fill=tk.X, padx=40, pady=(0, 0))

    tk.Label(
        card,
        text="Configuration Folder",
        font=("Segoe UI", 16, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(anchor=tk.W, pady=(20, 4), padx=20)

    tk.Label(
        card,
        text=(
            "By default, your account data and configurations are stored in the standard location. "
            "You can select a custom folder if you want to move your configuration to a different location."
        ),
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        wraplength=760,
        justify=tk.LEFT,
    ).pack(anchor=tk.W, fill=tk.X, padx=20, pady=(0, 10))

    config_folder_frame = tk.Frame(card, bg=PROXMOX_MEDIUM)
    config_folder_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

    default_config_dir = str(Path.home() / ".config" / "Proxmox-LDC")
    current_config_dir = get_preference(root, "config_dir", default_config_dir)
    
    config_dir_var = tk.StringVar(value=current_config_dir)
    status_var = tk.StringVar(value="")

    tk.Label(
        config_folder_frame,
        text="Config Folder:",
        font=("Segoe UI", 11, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
        width=15,
        anchor="w",
    ).pack(side=tk.LEFT, padx=(0, 10))

    config_entry = tk.Entry(
        config_folder_frame,
        textvariable=config_dir_var,
        font=("Segoe UI", 11),
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        bd=0,
        relief="flat",
        highlightthickness=1,
        highlightbackground="#363c45",
        highlightcolor=PROXMOX_ORANGE,
    )
    config_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

    def browse_folder() -> None:
        """Open folder selection dialog."""
        current_path = config_dir_var.get().strip()
        if current_path:
            try:
                initial_dir = Path(current_path).parent if Path(current_path).is_file() else current_path
            except Exception:
                initial_dir = Path.home()
        else:
            initial_dir = Path.home()
        
        folder = filedialog.askdirectory(
            title="Select Configuration Folder",
            initialdir=str(initial_dir),
            parent=root,
        )
        if folder:
            config_dir_var.set(folder)

    tk.Button(
        config_folder_frame,
        text="Browse...",
        command=browse_folder,
        font=("Segoe UI", 10, "bold"),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=14,
        pady=6,
    ).pack(side=tk.LEFT)

    def save_config_folder() -> None:
        """Save the custom config folder preference and optionally copy existing data."""
        new_path = config_dir_var.get().strip()
        
        if not new_path:
            messagebox.showerror(
                "Invalid path",
                "Please enter a valid folder path.",
                parent=root,
            )
            return
        
        # Validate the path
        try:
            path_obj = Path(new_path)
            # Check if it's a valid path (doesn't need to exist yet)
            if not path_obj.is_absolute():
                messagebox.showerror(
                    "Invalid path",
                    "Please enter an absolute path.",
                    parent=root,
                )
                return
        except Exception as exc:
            messagebox.showerror(
                "Invalid path",
                f"Invalid folder path: {exc}",
                parent=root,
            )
            return
        
        # Check if we're changing from the default location
        default_config = Path.home() / ".config" / "Proxmox-LDC"
        old_path = Path(current_config_dir)
        
        # Check if old location has data and new location doesn't
        should_copy = False
        if old_path.exists() and old_path != path_obj:
            accounts_dir = old_path / "Accounts"
            if accounts_dir.exists() and any(accounts_dir.iterdir()):
                # Old location has accounts
                new_accounts_dir = path_obj / "Accounts"
                if not new_accounts_dir.exists() or not any(new_accounts_dir.iterdir()):
                    # New location doesn't have accounts - offer to copy
                    should_copy = True
        
        if should_copy:
            # Ask user if they want to copy existing data
            response = messagebox.askyesno(
                "Copy Existing Data?",
                (
                    f"Your current configuration folder contains account data.\n\n"
                    f"Would you like to copy all existing data from:\n{old_path}\n\n"
                    f"to the new location:\n{new_path}\n\n"
                    f"If you choose 'No', you'll need to manually copy the data later."
                ),
                parent=root,
            )
            
            if response:
                # Copy the data
                try:
                    # Create new directory structure
                    path_obj.mkdir(parents=True, exist_ok=True)
                    new_accounts_dir = path_obj / "Accounts"
                    new_accounts_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Copy Accounts directory
                    if (old_path / "Accounts").exists():
                        for account_dir in (old_path / "Accounts").iterdir():
                            if account_dir.is_dir():
                                dest_dir = new_accounts_dir / account_dir.name
                                if dest_dir.exists():
                                    # Skip if already exists
                                    continue
                                shutil.copytree(account_dir, dest_dir)
                    
                    # Copy any other files in the config directory
                    for item in old_path.iterdir():
                        if item.is_file() and item.name != "preferences.json":
                            dest_file = path_obj / item.name
                            if not dest_file.exists():
                                shutil.copy2(item, dest_file)
                    
                    status_var.set("Configuration folder changed and data copied successfully. Restart the app for changes to take effect.")
                except Exception as exc:
                    messagebox.showerror(
                        "Copy Error",
                        f"Failed to copy configuration data:\n{exc}\n\n"
                        f"The folder preference will still be saved, but you may need to manually copy your data.",
                        parent=root,
                    )
                    status_var.set("Configuration folder preference saved (data copy failed). Restart the app for changes to take effect.")
            else:
                status_var.set("Configuration folder preference saved. You'll need to manually copy your data. Restart the app for changes to take effect.")
        else:
            status_var.set("Configuration folder preference saved. Restart the app for changes to take effect.")
        
        # Save the preference in both the account and a global preferences file
        set_preference(root, "config_dir", new_path)
        
        # Also save to a global preferences file in the default location
        # so it can be read on next startup before account is loaded
        import json
        default_config.mkdir(parents=True, exist_ok=True)
        pref_file = default_config / "preferences.json"
        try:
            prefs = {}
            if pref_file.exists():
                with pref_file.open("r", encoding="utf-8") as f:
                    prefs = json.load(f)
            prefs["config_dir"] = new_path
            with pref_file.open("w", encoding="utf-8") as f:
                json.dump(prefs, f, indent=2)
        except Exception as exc:
            messagebox.showerror(
                "Save error",
                f"Could not save preference file: {exc}",
                parent=root,
            )
            return

    save_button_frame = tk.Frame(card, bg=PROXMOX_MEDIUM)
    save_button_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

    tk.Button(
        save_button_frame,
        text="Save Folder Preference",
        command=save_config_folder,
        font=("Segoe UI", 11, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=8,
    ).pack(side=tk.LEFT)

    status_label = tk.Label(
        save_button_frame,
        textvariable=status_var,
        font=("Segoe UI", 10),
        fg="#7ddc88",
        bg=PROXMOX_MEDIUM,
    )
    status_label.pack(side=tk.LEFT, padx=(15, 0))

    tk.Label(
        card,
        text="Note: You must restart the application for the new configuration folder to take effect.",
        font=("Segoe UI", 10),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        wraplength=760,
        justify=tk.LEFT,
    ).pack(anchor=tk.W, fill=tk.X, padx=20, pady=(0, 20))

    return frame

