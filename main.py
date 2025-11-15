import threading
import time
import tkinter as tk
from tkinter import font, ttk
from typing import Any

from add_container_view import build_view as build_add_container_view
from add_vm_view import build_view as build_add_vm_view
from app_settings_view import build_view as build_app_settings_view
from manage_containers_view import build_view as build_manage_containers_view
from manage_vms_view import build_view as build_manage_vms_view
from proxmox_client import ProxmoxAPIError, ProxmoxClient, ProxmoxSummary
from server_settings_view import build_view as build_server_settings_view
from shell_view import build_view as build_shell_view
from theme import (
    PROXMOX_ACCENT,
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
)
from wizard import AccountStore, SetupWizard

WINDOW_WIDTH = 1024
WINDOW_HEIGHT = 768


def format_bytes(amount: int | float | None) -> str:
    if not amount:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(amount)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_percentage(used: int | float | None, total: int | float | None) -> str:
    if not used or not total or total == 0:
        return "0%"
    return f"{(used / total) * 100:.1f}%"


def format_duration(seconds: int | None) -> str:
    if not seconds:
        return "N/A"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{sec}s")
    return " ".join(parts)


def clear_content(root: tk.Tk) -> None:
    for widget in root.content_frame.winfo_children():
        widget.destroy()


CARD_MIN_WIDTH = 420
AUTO_REFRESH_INTERVAL_MS = 15000
AUTO_REFRESH_INTERVAL_MS = 15000


def get_preferences(root: tk.Tk) -> dict:
    account = root.app_state.get("account")  # type: ignore[index]
    if not account:
        return {}
    return account.setdefault("preferences", {})


def get_preference(root: tk.Tk, key: str, default: str) -> str:
    prefs = get_preferences(root)
    return prefs.get(key, default)


def set_preference(root: tk.Tk, key: str, value: str) -> None:
    account = root.app_state.get("account")  # type: ignore[index]
    if not account:
        return
    prefs = account.setdefault("preferences", {})
    if prefs.get(key) == value:
        return
    prefs[key] = value
    store = getattr(root, "account_store", None)
    if store:
        store.save_account(account)


def create_card(parent: tk.Widget, title: str) -> tuple[tk.Frame, tk.Frame]:
    card = tk.Frame(parent, bg=PROXMOX_MEDIUM, highlightthickness=0, bd=0)
    heading = tk.Label(
        card,
        text=title,
        font=("Segoe UI", 18, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    )
    heading.pack(anchor=tk.W, pady=(10, 5), padx=15)
    divider = tk.Frame(card, bg=PROXMOX_ORANGE, height=2)
    divider.pack(fill=tk.X, padx=15, pady=(0, 15))
    body = tk.Frame(card, bg=PROXMOX_MEDIUM)
    body.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    return card, body


def add_stat_row(parent: tk.Widget, label_text: str, value_text: str) -> None:
    row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
    row.pack(fill=tk.X, pady=4)
    label = tk.Label(
        row,
        text=label_text,
        font=("Segoe UI", 11, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
        width=22,
        anchor="w",
    )
    label.pack(side=tk.LEFT)
    value = tk.Label(
        row,
        text=value_text,
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_MEDIUM,
        justify=tk.LEFT,
        wraplength=600,
    )
    value.pack(side=tk.LEFT, fill=tk.X, expand=True)


def layout_cards(container: tk.Widget, cards: list[tk.Frame]) -> None:
    if not cards:
        return

    width = max(container.winfo_width(), CARD_MIN_WIDTH)
    columns = max(1, width // (CARD_MIN_WIDTH + 20))

    for card in cards:
        card.grid_forget()

    for idx, card in enumerate(cards):
        row = idx // columns
        col = idx % columns
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        container.grid_columnconfigure(col, weight=1)


def confirm_dialog(title: str, message: str, root: tk.Tk) -> bool:
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.configure(bg=PROXMOX_DARK)
    dialog.transient(root)
    dialog.grab_set()

    tk.Label(
        dialog,
        text=title,
        font=("Segoe UI", 13, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    ).pack(anchor=tk.W, padx=30, pady=(20, 5))

    tk.Label(
        dialog,
        text=message,
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_DARK,
        wraplength=420,
        justify=tk.LEFT,
    ).pack(fill=tk.X, padx=30, pady=(0, 15))

    response = {"value": False}

    def choose(value: bool) -> None:
        response["value"] = value
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))
    tk.Button(
        buttons,
        text="Cancel",
        command=lambda: choose(False),
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=16,
        pady=6,
    ).pack(side=tk.RIGHT, padx=(10, 0))
    tk.Button(
        buttons,
        text="Confirm",
        command=lambda: choose(True),
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=16,
        pady=6,
    ).pack(side=tk.RIGHT)

    dialog.wait_window()
    return response["value"]


def render_dashboard(root: tk.Tk, account: dict | None) -> None:
    clear_content(root)
    root.title("Proxmox-LDC | Home")
    root.app_state["current_view"] = "home"  # type: ignore[index]

    container = tk.Frame(root.content_frame, bg=PROXMOX_DARK)
    container.pack(fill=tk.BOTH, expand=True)

    header_font = font.Font(family="Helvetica", size=36, weight="bold")

    header = tk.Label(
        container,
        text="Proxmox-LDC",
        font=header_font,
        fg=PROXMOX_ORANGE,
        bg=PROXMOX_DARK,
    )
    header.pack(pady=(30, 10))

    data: dict[str, Any] | None = root.app_state.get("dashboard_data")  # type: ignore[index]
    loading = root.app_state.get("dashboard_loading", False)  # type: ignore[index]

    if not account:
        tk.Label(
            container,
            text="No account configured. Please run the setup wizard.",
            font=("Segoe UI", 12),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
        ).pack(pady=30)
        return

    summary: ProxmoxSummary | None = data.get("summary") if data else None
    error = data.get("error") if data else None

    status_text = None
    if loading:
        status_text = "Loading latest Proxmox data..."
    elif not summary and not error:
        status_text = "Preparing to fetch Proxmox data..."

    if status_text:
        tk.Label(
            container,
            text=status_text,
            font=("Segoe UI", 12),
            fg="#cfd3da",
            bg=PROXMOX_DARK,
        ).pack(pady=(0, 20))

    cards_frame = tk.Frame(container, bg=PROXMOX_DARK)
    cards_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 20))
    cards: list[tk.Frame] = []

    if error:
        error_card, error_body = create_card(cards_frame, "Unable to load data")
        cards.append(error_card)
        tk.Label(
            error_body,
            text=str(error),
            font=("Segoe UI", 11),
            fg="#ffb3a7",
            bg=PROXMOX_MEDIUM,
            wraplength=900,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 10))
        tk.Button(
            error_body,
            text="Retry",
            command=lambda: fetch_dashboard_data(root, mode="full", force=True),
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            bd=0,
            padx=16,
            pady=8,
        ).pack(anchor=tk.W)
        layout_cards(cards_frame, cards)
        return

    if not summary:
        return

    widgets: dict[str, dict] = {}
    widgets["host"] = render_specs_section(cards_frame, summary, account, cards)
    widgets["network"] = render_network_section(cards_frame, summary, cards)
    widgets["storage"] = render_storage_section(cards_frame, summary, cards)
    widgets["vm"] = render_vm_section(cards_frame, summary, cards)
    widgets["container"] = render_container_section(cards_frame, summary, cards)
    layout_cards(cards_frame, cards)
    cards_frame.bind(
        "<Configure>",
        lambda event, cf=cards_frame, c=cards: layout_cards(cf, c),
    )
    root.app_state["dashboard_widgets"] = widgets  # type: ignore[index]


def update_dashboard_views(root: tk.Tk, account: dict | None, summary: ProxmoxSummary) -> None:
    widgets = root.app_state.get("dashboard_widgets")  # type: ignore[index]
    if not widgets or account is None:
        render_dashboard(root, account)
        return

    widgets["host"]["update"](summary, account)
    widgets["network"]["update"](summary)
    widgets["storage"]["update"](summary)
    widgets["vm"]["update"](summary)
    widgets["container"]["update"](summary)


def open_update_view(root: tk.Tk) -> None:
    account = root.app_state.get("account")  # type: ignore[index]
    summary: ProxmoxSummary | None = (
        root.app_state.get("dashboard_data", {}).get("summary")  # type: ignore[index]
    )
    if not account or not summary or not summary.node_name:
        messagebox.showwarning("Unavailable", "No Proxmox node information available yet.")
        return

    proxmox_cfg = account.get("proxmox", {})
    host = proxmox_cfg.get("host")
    username = proxmox_cfg.get("username")
    password = proxmox_cfg.get("password")
    verify_ssl = proxmox_cfg.get("verify_ssl", False)
    node_name = summary.node_name

    if not all([host, username, password]):
        messagebox.showwarning("Missing credentials", "Proxmox credentials are incomplete.")
        return

    clear_content(root)
    root.title("Proxmox-LDC | Updates")
    root.app_state["current_view"] = "Updates"  # type: ignore[index]

    container = tk.Frame(root.content_frame, bg=PROXMOX_DARK)
    container.pack(fill=tk.BOTH, expand=True)

    header = tk.Label(
        container,
        text=f"Check for updates on {node_name}",
        font=("Segoe UI", 16, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_DARK,
    )
    header.pack(anchor=tk.W, padx=30, pady=(20, 5))

    info = tk.Label(
        container,
        text="Review pending updates, then confirm to install them via the Proxmox API.",
        font=("Segoe UI", 11),
        fg="#cfd3da",
        bg=PROXMOX_DARK,
    )
    info.pack(anchor=tk.W, padx=30, pady=(0, 5))

    repo_alert = tk.Label(
        container,
        text="",
        font=("Segoe UI", 10, "bold"),
        fg="#ffb74d",
        bg=PROXMOX_DARK,
        justify=tk.LEFT,
        wraplength=640,
    )
    repo_alert.pack(anchor=tk.W, padx=30, pady=(0, 10))

    text_frame = tk.Frame(container, bg=PROXMOX_DARK)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 10))

    scrollbar = tk.Scrollbar(text_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    output = tk.Text(
        text_frame,
        bg=PROXMOX_MEDIUM,
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        wrap=tk.WORD,
        yscrollcommand=scrollbar.set,
        state=tk.DISABLED,
    )
    output.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=output.yview)

    buttons = tk.Frame(container, bg=PROXMOX_DARK)
    buttons.pack(fill=tk.X, padx=30, pady=(0, 20))
    install_button_container = {"packed": False}
    install_button = tk.Button(
        buttons,
        text="Install updates",
        state=tk.DISABLED,
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=12,
        pady=6,
    )
    # Defer packing until we know updates exist.

    tk.Button(
        buttons,
        text="Close",
        command=lambda: go_home(root),
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    ).pack(side=tk.RIGHT, padx=(10, 0))

    stop_button = tk.Button(
        buttons,
        text="Stop",
        state=tk.DISABLED,
        font=("Segoe UI", 10),
        bg="#f44336",
        fg="white",
        activebackground="#ff5f52",
        activeforeground="white",
        bd=0,
        padx=12,
        pady=6,
    )
    stop_button.pack(side=tk.RIGHT, padx=(10, 0))

    check_button = tk.Button(
        buttons,
        text="Check for updates",
        font=("Segoe UI", 10),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=6,
    )
    check_button.pack(side=tk.RIGHT)

    def log(message: str) -> None:
        output.configure(state=tk.NORMAL)
        output.insert(tk.END, message + "\n")
        output.see(tk.END)
        output.configure(state=tk.DISABLED)
        action_state["logs"].append(message)

    def run_in_thread(action):
        def wrapper():
            try:
                client = ProxmoxClient(host=host, username=username, password=password, verify_ssl=verify_ssl)
                return action(client)
            finally:
                if 'client' in locals():
                    client.close()

        thread = threading.Thread(target=lambda: thread_task(wrapper), daemon=True)
        thread.start()

    def thread_task(callable_fn):
        try:
            result = callable_fn()
            root.after(0, lambda r=result: handle_result(r))
        except ProxmoxAPIError as exc:
            root.after(0, lambda e=str(exc): handle_error(e))
        except Exception as exc:  # pragma: no cover
            root.after(0, lambda e=str(exc): handle_error(f"Unexpected error: {e}"))

    # To differentiate between check/install results.
    action_state = {"mode": None, "updates": [], "upid": None, "monitoring": False, "logs": []}

    def ensure_install_button_visible():
        if not install_button_container["packed"]:
            install_button.pack(side=tk.RIGHT, padx=(10, 0))
            install_button_container["packed"] = True

    def handle_result(result):
        mode = action_state["mode"]
        if mode == "check":
            updates = result.get("updates") if isinstance(result, dict) else result or []
            repos_ok = result.get("repos_ok") if isinstance(result, dict) else True
            if not repos_ok:
                update_repo_alert(
                    "Enterprise repositories detected without subscription.",
                    instructions=True,
                )
            else:
                repo_alert.config(text="")

            action_state["updates"] = updates
            if not updates:
                log("System is up to date. No packages pending.")
                install_button.config(state=tk.DISABLED)
            else:
                log("Pending updates:\n")
                for pkg in updates:
                    name = (
                        pkg.get("package")
                        or pkg.get("Title")
                        or pkg.get("title")
                        or "unknown"
                    )
                    version = (
                        pkg.get("Version")
                        or pkg.get("version")
                        or pkg.get("current-version")
                        or pkg.get("OldVersion")
                        or ""
                    )
                    origin = pkg.get("origin") or pkg.get("repo") or pkg.get("ChangeLogUrl") or ""
                    log(f"- {name} {version} ({origin})")
                ensure_install_button_visible()
                install_button.config(state=tk.NORMAL)
                check_button.config(state=tk.NORMAL)
        elif mode == "install":
            if isinstance(result, dict) and result.get("manual_required"):
                log(
                    "Automatic upgrade is not supported on this Proxmox version.\n"
                    "Please run on the host:\n"
                    "  apt-get update && apt-get dist-upgrade"
                )
                install_button.config(state=tk.NORMAL)
                check_button.config(state=tk.NORMAL)
                return
            task_data = result.get("task") if isinstance(result, dict) else result
            upid = (
                task_data
                if isinstance(task_data, str)
                else task_data.get("upid")
                if isinstance(task_data, dict)
                else None
            )
            if upid:
                action_state["upid"] = upid
                log(f"Update task started: {upid}")
                start_task_monitor(upid)
            else:
                log("Update command triggered successfully. Monitor Proxmox task log for progress.")
            install_button.config(state=tk.DISABLED)

    def handle_error(message: str) -> None:
        log(f"Error: {message}")
        action_state["monitoring"] = False
        stop_button.config(state=tk.DISABLED)
        check_button.config(state=tk.NORMAL)
        install_button.config(state=tk.DISABLED)

    def check_updates() -> None:
        action_state["mode"] = "check"
        log("Refreshing package cache and checking for updates...")
        check_button.config(state=tk.DISABLED)
        install_button.config(state=tk.DISABLED)

        def action(client: ProxmoxClient):
            client.refresh_apt_cache(node_name)
            repos_ok = check_repos_for_subscription(client)
            updates = client.list_available_updates(node_name)
            return {"updates": updates, "repos_ok": repos_ok}

        run_in_thread(action)

    def install_updates() -> None:
        if not action_state["updates"]:
            messagebox.showinfo("No updates", "No updates are queued for installation.")
            return
        if not confirm_dialog("Install updates", "Install all pending updates now?", root):
            return

        action_state["mode"] = "install"
        log("Starting update installation...")
        check_button.config(state=tk.DISABLED)
        install_button.config(state=tk.DISABLED)

        def action(client: ProxmoxClient):
            try:
                return {"task": client.upgrade_packages(node_name)}
            except ProxmoxAPIError as exc:
                if "apt/upgrade" in str(exc):
                    return {"manual_required": True, "error": str(exc)}
                raise

        run_in_thread(action)

    def append_task_logs(entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            line = entry.get("t")
            if line:
                log(line.rstrip())

    def finalize_task(status: dict[str, Any]) -> None:
        action_state["monitoring"] = False
        exitstatus = status.get("exitstatus") or status.get("status")
        log(f"Task finished with status: {exitstatus}")
        check_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

    def start_task_monitor(upid: str) -> None:
        if action_state.get("monitoring"):
            return
        action_state["monitoring"] = True

        def monitor():
            start = 0
            client = None
            try:
                client = ProxmoxClient(host=host, username=username, password=password, verify_ssl=verify_ssl)
                stop_button.config(state=tk.NORMAL)
                while action_state["monitoring"]:
                    logs = client.get_task_log(node_name, upid, start=start)
                    if logs:
                        start = logs[-1].get("n", start) + 1
                        root.after(0, lambda entries=list(logs): append_task_logs(entries))
                    status = client.get_task_status(node_name, upid)
                    if status.get("status") == "stopped":
                        root.after(0, lambda st=status: finalize_task(st))
                        break
                    time.sleep(2)
            except ProxmoxAPIError as exc:
                root.after(0, lambda e=str(exc): handle_error(e))
            except Exception as exc:  # pragma: no cover
                root.after(0, lambda e=str(exc): handle_error(f"Unexpected error: {e}"))
            finally:
                action_state["monitoring"] = False
                stop_button.config(state=tk.DISABLED)
                if client:
                    client.close()

        threading.Thread(target=monitor, daemon=True).start()

    def stop_task() -> None:
        upid = action_state.get("upid")
        if not upid:
            return

        def action(client: ProxmoxClient):
            client.stop_task(node_name, upid)

        run_in_thread(action)
        log("Attempting to stop the update task...")

    def update_repo_alert(message: str, instructions: bool = False) -> None:
        repo_alert.config(text=message)
        if instructions:
            manual_steps = (
                "\n\nManual steps:\n"
                "1. SSH into the Proxmox host (ssh root@<host>).\n"
                "2. Edit /etc/apt/sources.list.d/pve-enterprise.list and comment out the enterprise entry.\n"
                "3. Add: deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n"
                "4. (Optional) Edit ceph list file similarly: deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription\n"
                "5. Run apt update on the host, then return here."
            )
            full_message = f"{message}{manual_steps}"
            repo_alert.config(text=full_message)
        log(message)

    def check_repos_for_subscription(client: ProxmoxClient) -> bool:
        repos = client.list_repositories(node_name)
        for repo in repos:
            name = (repo.get("name") or repo.get("handle") or "").lower()
            status = repo.get("status")
            if "enterprise" in name and status == "enabled":
                return False
        return True
    stop_button.config(command=stop_task)
    check_button.config(command=check_updates)
    install_button.config(command=install_updates)
    check_updates()

def render_specs_section(
    parent: tk.Widget, summary: ProxmoxSummary, account: dict, cards: list[tk.Frame]
) -> dict:
    card, body = create_card(parent, "Proxmox Host Overview")
    cards.append(card)

    root = parent.winfo_toplevel()
    button_row = tk.Frame(card, bg=PROXMOX_MEDIUM)
    button_row.pack(anchor=tk.E, padx=15, pady=(0, 5))

    tk.Button(
        button_row,
        text="Check for updates",
        command=lambda: open_update_view(root),
        font=("Segoe UI", 10, "bold"),
        bg="#2f3640",
        fg=PROXMOX_LIGHT,
        activebackground="#3a414d",
        activeforeground=PROXMOX_LIGHT,
        bd=0,
        padx=12,
        pady=4,
    ).pack(side=tk.RIGHT, padx=(10, 0))

    tk.Button(
        button_row,
        text="Refresh data",
        command=lambda: request_manual_refresh(root),
        font=("Segoe UI", 10, "bold"),
        bg=PROXMOX_ORANGE,
        fg="white",
        activebackground="#ff8126",
        activeforeground="white",
        bd=0,
        padx=12,
        pady=4,
    ).pack(side=tk.RIGHT)

    grid = tk.Frame(body, bg=PROXMOX_MEDIUM)
    grid.pack(fill=tk.X)

    def populate(summary_obj: ProxmoxSummary, account_obj: dict) -> None:
        for child in grid.winfo_children():
            child.destroy()

        version = summary_obj.version.get("version", "Unknown")
        release = summary_obj.version.get("release")
        version_text = f"{version} ({release})" if release else version
        add_stat_row(grid, "Proxmox Version", version_text)

        node_name = summary_obj.node_name or "Unknown"
        add_stat_row(grid, "Node", node_name)
        add_stat_row(grid, "Host", account_obj["proxmox"]["host"])

        node_status = summary_obj.node_status or {}
        add_stat_row(grid, "Status", node_status.get("status", "Unknown"))
        add_stat_row(grid, "Kernel", node_status.get("kversion", "Unknown"))
        add_stat_row(grid, "PVE Build", node_status.get("pveversion", "Unknown"))

        cpuinfo = node_status.get("cpuinfo", {})
        cpu_model = cpuinfo.get("model", "Unknown CPU")
        sockets = cpuinfo.get("sockets")
        cores = cpuinfo.get("cores")
        cpu_details = cpu_model
        if sockets and cores:
            cpu_details += f" ({sockets} sockets / {cores} cores)"
        add_stat_row(grid, "Processor", cpu_details)

        loadavg = node_status.get("loadavg")
        if isinstance(loadavg, list) and loadavg:
            load_text = ", ".join(str(v) for v in loadavg[:3])
            add_stat_row(grid, "Load Average", load_text)

        uptime = summary_obj.node_status.get("uptime") if summary_obj.node_status else None
        add_stat_row(grid, "Uptime", format_duration(uptime))

        memory = node_status.get("memory", {})
        mem_total = memory.get("total")
        mem_used = memory.get("used")
        mem_text = (
            f"{format_bytes(mem_used)} used / {format_bytes(mem_total)} total "
            f"({format_percentage(mem_used, mem_total)})"
        )
        add_stat_row(grid, "RAM", mem_text)

    populate(summary, account)
    return {"card": card, "update": populate}


def render_network_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Network Interfaces")
    cards.append(section)
    data_holder = {
        "items": [iface for iface in summary.network if iface.get("iface")]
    }

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "network_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "network_sort", sort_var.get())
        update_interface_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("status_up"),
            ("status_down"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_interfaces() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            iface
            for iface in data_holder["items"]
            if term in iface.get("iface", "").lower()
            or term in (iface.get("address") or iface.get("ip-address") or "").lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda iface: iface.get("iface", "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda iface: iface.get("iface", "").lower())
        elif key == "status_up":
            filtered.sort(key=lambda iface: 0 if iface.get("status") == "active" else 1)
        elif key == "status_down":
            filtered.sort(key=lambda iface: 0 if iface.get("status") != "active" else 1)
        return filtered

    def update_interface_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_interfaces()
        if not items:
            tk.Label(
                list_container,
                text="No matching interfaces.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for iface in items:
            render_interface_row(list_container, iface)

    def render_interface_row(parent: tk.Frame, iface: dict[str, Any]) -> None:
        name = iface.get("iface", "Unknown")
        address = iface.get("address") or iface.get("ip-address") or "N/A"
        status = iface.get("status")
        active_flag = iface.get("active", False)
        is_up = bool(active_flag) or (isinstance(status, str) and status.lower() in {"active", "up", "connected"})
        status_text = "UP" if is_up else "DOWN"
        status_color = "#4caf50" if is_up else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=address,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=status_text,
            font=("Segoe UI", 10, "bold"),
            fg=status_color,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT)

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, iface_data=iface, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_interface_details(frame, iface_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"Type: {iface.get('type', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    def render_interface_details(container_frame: tk.Frame, iface: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        status = iface.get("status")
        active_flag = iface.get("active", False)
        is_up = bool(active_flag) or (isinstance(status, str) and status.lower() in {"active", "up", "connected"})

        details = [
            ("Interface", iface.get("iface", "Unknown")),
            ("Status", "UP" if is_up else "DOWN"),
            ("Type", iface.get("type", "unknown")),
            ("Method", iface.get("method", "unknown")),
            ("Address", iface.get("address") or iface.get("ip-address") or "N/A"),
            ("MAC", iface.get("mac") or iface.get("hwaddr") or "N/A"),
            ("Bridge Ports", iface.get("bridge_ports") or "N/A"),
            ("Autostart", str(iface.get("autostart", False))),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_interface_list()
    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = [iface for iface in summary_obj.network if iface.get("iface")]
        update_interface_list()

    return {"card": section, "update": refresh}


def render_storage_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Storage Devices")
    cards.append(section)
    data_holder = {"items": list(summary.storage)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "storage_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "storage_sort", sort_var.get())
        update_storage_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("capacity_asc"),
            ("capacity_desc"),
            ("usage_asc"),
            ("usage_desc"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_storage() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            entry
            for entry in data_holder["items"]
            if term in (entry.get("storage") or "").lower()
            or term in (entry.get("type") or "").lower()
            or term in (entry.get("node") or "").lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda entry: (entry.get("storage") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda entry: (entry.get("storage") or "").lower())
        elif key == "capacity_desc":
            filtered.sort(key=lambda entry: entry.get("total", 0), reverse=True)
        elif key == "capacity_asc":
            filtered.sort(key=lambda entry: entry.get("total", 0))
        elif key == "usage_desc":
            filtered.sort(key=lambda entry: entry.get("used", 0), reverse=True)
        elif key == "usage_asc":
            filtered.sort(key=lambda entry: entry.get("used", 0))
        return filtered

    def update_storage_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_storage()
        if not items:
            tk.Label(
                list_container,
                text="No matching storage devices.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for entry in items:
            render_storage_row(list_container, entry)

    def render_storage_row(parent: tk.Frame, entry: dict[str, Any]) -> None:
        name = entry.get("storage", "Unnamed")
        storage_type = entry.get("type", "Unknown")

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row,
            text=f"Type: {storage_type}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, entry_data=entry, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_storage_details(frame, entry_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

    def render_storage_details(container_frame: tk.Frame, entry: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        details = [
            ("Type", entry.get("type", "Unknown")),
            ("Node", entry.get("node", "Unknown")),
            ("Enabled", str(entry.get("enabled", True))),
            ("Shared", str(entry.get("shared", False))),
            ("Content", ", ".join(entry.get("content", "").split(",")) if entry.get("content") else "N/A"),
            ("Used", format_bytes(entry.get("used"))),
            ("Total", format_bytes(entry.get("total"))),
            ("Free", format_bytes(entry.get("total", 0) - entry.get("used", 0))),
            ("Usage", format_percentage(entry.get("used"), entry.get("total"))),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_storage_list()
    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.storage)
        update_storage_list()

    return {"card": section, "update": refresh}


def render_vm_section(
    parent: tk.Widget,
    summary: ProxmoxSummary,
    cards: list[tk.Frame],
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "Virtual Machines")
    cards.append(section)
    data_holder = {"items": list(summary.vms)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "vm_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "vm_sort", sort_var.get())
        update_vm_list()

    combobox_style = ttk.Style()
    combobox_style.theme_use("clam")
    combobox_style.configure(
        "Proxmox.TCombobox",
        fieldbackground="#1f242b",
        background="#1f242b",
        foreground=PROXMOX_LIGHT,
        bordercolor="#3a414d",
        arrowcolor=PROXMOX_LIGHT,
        padding=5,
        relief="flat",
        selectbackground="#2f3640",
        selectforeground=PROXMOX_LIGHT,
    )
    combobox_style.map(
        "Proxmox.TCombobox",
        fieldbackground=[("readonly", "#1f242b")],
        foreground=[("readonly", PROXMOX_LIGHT)],
    )

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("id_asc"),
            ("id_desc"),
            ("running_first"),
            ("stopped_first"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_vms() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            vm
            for vm in data_holder["items"]
            if term in (vm.get("name") or "").lower()
            or term in str(vm.get("vmid")).lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda vm: (vm.get("name") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda vm: (vm.get("name") or "").lower())
        elif key == "id_desc":
            filtered.sort(key=lambda vm: vm.get("vmid", 0), reverse=True)
        elif key == "id_asc":
            filtered.sort(key=lambda vm: vm.get("vmid", 0))
        elif key == "running_first":
            filtered.sort(key=lambda vm: 0 if vm.get("status") == "running" else 1)
        elif key == "stopped_first":
            filtered.sort(key=lambda vm: 0 if vm.get("status") != "running" else 1)
        return filtered

    def update_vm_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_vms()
        if not items:
            tk.Label(
                list_container,
                text="No matching VMs.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for vm in items:
            render_vm_row(list_container, vm)

    def render_vm_row(parent: tk.Frame, vm: dict[str, Any]) -> None:
        name = vm.get("name") or f"VM {vm.get('vmid')}"
        status = vm.get("status", "stopped")
        status_color = "#4caf50" if status == "running" else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, vm_data=vm, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_vm_details(frame, vm_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"VMID: {vm.get('vmid', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    update_vm_list()

    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.vms)
        update_vm_list()

    return {"card": section, "update": refresh}



def render_container_section(
    parent: tk.Widget, summary: ProxmoxSummary, cards: list[tk.Frame]
) -> dict:
    root = parent.winfo_toplevel()
    section, body = create_card(parent, "LXC Containers")
    cards.append(section)
    data_holder = {"items": list(summary.containers)}

    controls = tk.Frame(body, bg=PROXMOX_MEDIUM)
    controls.pack(fill=tk.X, pady=(0, 10))

    tk.Label(
        controls,
        text="Sort by:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    sort_var = tk.StringVar(value=get_preference(root, "container_sort", "name_asc"))

    def apply_filters(*args) -> None:
        set_preference(root, "container_sort", sort_var.get())
        update_ct_list()

    sort_menu = ttk.Combobox(
        controls,
        textvariable=sort_var,
        state="readonly",
        values=[
            ("name_asc"),
            ("name_desc"),
            ("id_asc"),
            ("id_desc"),
            ("running_first"),
            ("stopped_first"),
        ],
        width=18,
        style="Proxmox.TCombobox",
    )
    sort_menu.pack(side=tk.LEFT, padx=(8, 20))
    sort_menu.bind("<<ComboboxSelected>>", apply_filters)

    search_var = tk.StringVar()
    search_var.trace_add("write", lambda *_: apply_filters())

    tk.Label(
        controls,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        fg=PROXMOX_LIGHT,
        bg=PROXMOX_MEDIUM,
    ).pack(side=tk.LEFT)

    search_entry = tk.Entry(
        controls,
        textvariable=search_var,
        width=22,
        bg="#1f242b",
        fg=PROXMOX_LIGHT,
        insertbackground=PROXMOX_LIGHT,
        relief="flat",
        highlightbackground="#3a414d",
        highlightcolor=PROXMOX_ORANGE,
        highlightthickness=1,
        bd=0,
        insertwidth=1,
    )
    search_entry.pack(side=tk.LEFT, padx=(8, 0))

    separator = tk.Frame(body, bg="#333b47", height=1)
    separator.pack(fill=tk.X, pady=5)

    list_container = tk.Frame(body, bg=PROXMOX_MEDIUM)
    list_container.pack(fill=tk.BOTH, expand=True)

    def filtered_sorted_cts() -> list[dict[str, Any]]:
        term = search_var.get().strip().lower()
        filtered = [
            ct
            for ct in data_holder["items"]
            if term in (ct.get("name") or "").lower()
            or term in str(ct.get("vmid")).lower()
        ]

        key = sort_var.get()
        if key == "name_desc":
            filtered.sort(key=lambda ct: (ct.get("name") or "").lower(), reverse=True)
        elif key == "name_asc":
            filtered.sort(key=lambda ct: (ct.get("name") or "").lower())
        elif key == "id_desc":
            filtered.sort(key=lambda ct: ct.get("vmid", 0), reverse=True)
        elif key == "id_asc":
            filtered.sort(key=lambda ct: ct.get("vmid", 0))
        elif key == "running_first":
            filtered.sort(key=lambda ct: 0 if ct.get("status") == "running" else 1)
        elif key == "stopped_first":
            filtered.sort(key=lambda ct: 0 if ct.get("status") != "running" else 1)
        return filtered

    def update_ct_list() -> None:
        for child in list_container.winfo_children():
            child.destroy()

        items = filtered_sorted_cts()
        if not items:
            tk.Label(
                list_container,
                text="No matching containers.",
                font=("Segoe UI", 11),
                fg="#cfd3da",
                bg=PROXMOX_MEDIUM,
            ).pack(anchor=tk.W)
            return

        for ct in items:
            render_ct_row(list_container, ct)

    def render_ct_row(parent: tk.Frame, ct: dict[str, Any]) -> None:
        name = ct.get("name") or f"CT {ct.get('vmid')}"
        status = ct.get("status", "stopped")
        status_color = "#4caf50" if status == "running" else "#f44336"

        row = tk.Frame(parent, bg=PROXMOX_MEDIUM)
        row.pack(fill=tk.X, pady=4)

        status_indicator = tk.Canvas(row, width=14, height=14, bg=PROXMOX_MEDIUM, highlightthickness=0)
        status_indicator.create_oval(2, 2, 12, 12, fill=status_color, outline=status_color)
        status_indicator.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 12, "bold"),
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.LEFT, padx=(0, 10))

        toggle_text = tk.StringVar(value="Details ▾")
        details_frame = tk.Frame(parent, bg="#1f242b")

        def toggle_details(frame=details_frame, label_var=toggle_text, ct_data=ct, anchor=row) -> None:
            if frame.winfo_ismapped():
                frame.pack_forget()
                label_var.set("Details ▾")
            else:
                render_container_details(frame, ct_data)
                frame.pack(fill=tk.X, padx=4, pady=(2, 6), after=anchor)
                label_var.set("Details ▴")

        tk.Button(
            row,
            textvariable=toggle_text,
            command=toggle_details,
            font=("Segoe UI", 10),
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            activeforeground=PROXMOX_LIGHT,
            bd=0,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        tk.Label(
            row,
            text=f"CTID: {ct.get('vmid', 'N/A')}",
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg=PROXMOX_MEDIUM,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    def render_container_details(container_frame: tk.Frame, ct: dict[str, Any]) -> None:
        for child in container_frame.winfo_children():
            child.destroy()

        details = [
            ("CTID", str(ct.get("vmid", "N/A"))),
            ("Status", ct.get("status", "unknown")),
            ("Uptime", format_duration(ct.get("uptime"))),
            ("CPU Usage", f"{ct.get('cpu', 0)*100:.1f}%"),
            ("Memory", f"{format_bytes(ct.get('maxmem'))} max"),
            ("Disk", f"{format_bytes(ct.get('maxdisk'))} max"),
        ]

        for label, value in details:
            row = tk.Frame(container_frame, bg="#1f242b")
            row.pack(fill=tk.X, pady=1)
            tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                fg=PROXMOX_LIGHT,
                bg="#1f242b",
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row,
                text=value,
                font=("Segoe UI", 10),
                fg="#cfd3da",
                bg="#1f242b",
                anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    update_ct_list()

    def refresh(summary_obj: ProxmoxSummary) -> None:
        data_holder["items"] = list(summary_obj.containers)
        update_ct_list()

    return {"card": section, "update": refresh}


def render_vm_details(container: tk.Frame, vm: dict[str, Any]) -> None:
    for child in container.winfo_children():
        child.destroy()

    network_lines = []
    network_defs = vm.get("network") or []
    if isinstance(network_defs, list):
        for net in network_defs:
            iface_name = net.get("name", "net")
            bridge = net.get("bridge", "N/A")
            mac = net.get("mac", "N/A")
            model = net.get("model", "")
            network_lines.append(f"{iface_name} ({model}) -> {bridge}, MAC {mac}")

    details = [
        ("VMID", str(vm.get("vmid", "N/A"))),
        ("Status", vm.get("status", "unknown")),
        ("Uptime", format_duration(vm.get("uptime"))),
        ("CPU Usage", f"{vm.get('cpu', 0)*100:.1f}%"),
        ("Memory", f"{format_bytes(vm.get('maxmem'))} max"),
        ("Disk", f"{format_bytes(vm.get('maxdisk'))} max"),
        ("PID", str(vm.get("pid", "N/A"))),
        ("Networks", "\n".join(network_lines) if network_lines else "N/A"),
    ]

    for label, value in details:
        row = tk.Frame(container, bg="#1f242b")
        row.pack(fill=tk.X, pady=1)
        tk.Label(
            row,
            text=f"{label}:",
            font=("Segoe UI", 10, "bold"),
            fg=PROXMOX_LIGHT,
            bg="#1f242b",
            width=12,
            anchor="w",
        ).pack(side=tk.LEFT)
        tk.Label(
            row,
            text=value,
            font=("Segoe UI", 10),
            fg="#cfd3da",
            bg="#1f242b",
            anchor="w",
            justify=tk.LEFT,
            wraplength=750,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)


def show_setup_wizard(root: tk.Tk, store: AccountStore) -> None:
    clear_content(root)
    root.title("Proxmox-LDC | Setup")
    root.app_state["current_view"] = "setup"  # type: ignore[index]

    def on_complete(account: dict) -> None:
        wizard.destroy()
        root.app_state["account"] = account  # type: ignore[index]
        root.app_state["dashboard_data"] = None  # type: ignore[index]
        go_home(root)

    wizard = SetupWizard(root.content_frame, store, on_complete)
    wizard.pack(fill=tk.BOTH, expand=True)
    root.focus_force()


def create_root_window() -> tk.Tk:
    root = tk.Tk()
    root.title("Proxmox-LDC")
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    root.configure(bg=PROXMOX_DARK)
    root.app_state = {  # type: ignore[attr-defined]
        "account": None,
        "dashboard_data": None,
        "dashboard_loading": False,
        "current_view": "home",
    }
    root.option_add("*Menu.background", PROXMOX_MEDIUM)
    root.option_add("*Menu.foreground", PROXMOX_LIGHT)
    root.option_add("*Menu.activeBackground", PROXMOX_ORANGE)
    root.option_add("*Menu.activeForeground", "white")
    root.option_add("*Menu.relief", "flat")
    root.option_add("*Menu.font", "Helvetica 11")
    root.option_add("*Menu.selectColor", PROXMOX_ACCENT)

    container = tk.Frame(root, bg=PROXMOX_DARK)
    container.pack(fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(
        container,
        bg=PROXMOX_DARK,
        highlightthickness=0,
        borderwidth=0,
    )
    canvas.pack(fill=tk.BOTH, expand=True)

    content = tk.Frame(canvas, bg=PROXMOX_DARK)
    frame_window = canvas.create_window((0, 0), window=content, anchor="nw")

    def on_mousewheel(event: tk.Event) -> None:
        current_view = root.app_state.get("current_view")
        if str(current_view).lower() == "shell":
            return
        delta = event.delta
        if event.num == 4:  # Linux scroll up
            delta = 120
        elif event.num == 5:  # Linux scroll down
            delta = -120
        canvas.yview_scroll(int(-1 * (delta / 120)), "units")

    def on_key_scroll(event: tk.Event) -> None:  # pragma: no cover
        current_view = root.app_state.get("current_view")
        if str(current_view).lower() == "shell":
            return
        if event.keysym == "Up":
            canvas.yview_scroll(-1, "units")
        elif event.keysym == "Down":
            canvas.yview_scroll(1, "units")
        elif event.keysym == "Prior":  # Page Up
            canvas.yview_scroll(-8, "units")
        elif event.keysym == "Next":  # Page Down
            canvas.yview_scroll(8, "units")
        elif event.keysym == "Home":
            canvas.yview_moveto(0)
        elif event.keysym == "End":
            canvas.yview_moveto(1)

    root.bind_all("<MouseWheel>", on_mousewheel)
    root.bind_all("<Button-4>", on_mousewheel)
    root.bind_all("<Button-5>", on_mousewheel)
    root.bind_all("<Up>", on_key_scroll)
    root.bind_all("<Down>", on_key_scroll)
    root.bind_all("<Prior>", on_key_scroll)
    root.bind_all("<Next>", on_key_scroll)
    root.bind_all("<Home>", on_key_scroll)
    root.bind_all("<End>", on_key_scroll)

    def update_scroll_region(event: tk.Event) -> None:
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig(frame_window, width=canvas.winfo_width())

    content.bind("<Configure>", update_scroll_region)
    canvas.bind(
        "<Configure>",
        lambda event: canvas.itemconfig(frame_window, width=event.width),
    )

    root.content_canvas = canvas  # type: ignore[attr-defined]
    root.content_frame = content  # type: ignore[attr-defined]

    return root


def open_placeholder_view(root: tk.Tk, builder, title: str) -> None:
    clear_content(root)
    root.title(f"Proxmox-LDC | {title}")
    root.app_state["current_view"] = title  # type: ignore[index]
    frame = builder(root.content_frame)
    frame.pack(fill=tk.BOTH, expand=True)


def request_manual_refresh(root: tk.Tk) -> None:
    fetch_dashboard_data(root, mode="full", force=True)


def ensure_auto_refresh(root: tk.Tk) -> None:
    if getattr(root, "_auto_refresh_started", False):  # type: ignore[attr-defined]
        return
    root._auto_refresh_started = True  # type: ignore[attr-defined]

    def tick() -> None:
        if not root.winfo_exists():
            return
        if root.app_state.get("current_view") == "home":  # type: ignore[index]
            fetch_dashboard_data(root, mode="auto")
        root._auto_refresh_id = root.after(AUTO_REFRESH_INTERVAL_MS, tick)  # type: ignore[attr-defined]

    root._auto_refresh_id = root.after(AUTO_REFRESH_INTERVAL_MS, tick)  # type: ignore[attr-defined]


def go_home(root: tk.Tk) -> None:
    account = root.app_state.get("account")  # type: ignore[index]
    render_dashboard(root, account)
    fetch_dashboard_data(root, mode="full", force=True)
    ensure_auto_refresh(root)


def fetch_dashboard_data(root: tk.Tk, *, mode: str = "auto", force: bool = False) -> None:
    if root.app_state.get("dashboard_loading") and not force:  # type: ignore[index]
        return

    account = root.app_state.get("account")  # type: ignore[index]
    if not account:
        return

    proxmox = account.get("proxmox", {})
    host = proxmox.get("host")
    username = proxmox.get("username")
    password = proxmox.get("password")
    verify_ssl = proxmox.get("verify_ssl", False)

    if not all([host, username, password]):
        root.app_state["dashboard_data"] = {"error": "Incomplete Proxmox credentials."}  # type: ignore[index]
        if root.app_state.get("current_view") == "home":  # type: ignore[index]
            render_dashboard(root, account)
        return

    root.app_state["dashboard_loading"] = True  # type: ignore[index]

    existing_summary = (
        root.app_state.get("dashboard_data", {}).get("summary")  # type: ignore[index]
        if mode != "full"
        else None
    )

    def task() -> None:
        client: ProxmoxClient | None = None
        try:
            client = ProxmoxClient(
                host=host,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
            )
            if mode == "full" or existing_summary is None:
                summary = client.fetch_summary()
            else:
                summary = update_runtime_summary(client, existing_summary)
            payload = {"summary": summary}
        except ProxmoxAPIError as exc:
            payload = {"error": str(exc)}
        except Exception as exc:  # pragma: no cover
            payload = {"error": f"Unexpected error: {exc}"}
        finally:
            if client:
                client.close()

        root.after(0, lambda: _on_dashboard_data(root, payload))

    threading.Thread(target=task, daemon=True).start()


def _on_dashboard_data(root: tk.Tk, payload: dict[str, Any]) -> None:
    root.app_state["dashboard_loading"] = False  # type: ignore[index]
    root.app_state["dashboard_data"] = payload  # type: ignore[index]
    if root.app_state.get("current_view") == "home":  # type: ignore[index]
        summary = payload.get("summary")
        account = root.app_state.get("account")  # type: ignore[index]
        if summary and root.app_state.get("dashboard_widgets"):
            update_dashboard_views(root, account, summary)
        else:
            render_dashboard(root, account)


def update_runtime_summary(
    client: ProxmoxClient, existing: ProxmoxSummary
) -> ProxmoxSummary:
    node_name = existing.node_name
    if not node_name:
        return client.fetch_summary()

    node_status = client.get_node_status(node_name)
    vms_runtime = client.get_node_vms(node_name)
    containers_runtime = client.get_node_containers(node_name)

    existing_networks = {
        vm.get("vmid"): vm.get("network") for vm in existing.vms if vm.get("vmid") is not None
    }

    for vm in vms_runtime:
        net = existing_networks.get(vm.get("vmid"))
        if net:
            vm["network"] = net

    return ProxmoxSummary(
        version=existing.version,
        node_name=node_name,
        node_status=node_status,
        network=existing.network,
        storage=existing.storage,
        vms=vms_runtime,
        containers=containers_runtime,
    )


def setup_menu(root: tk.Tk) -> None:
    menu_kwargs = {
        "tearoff": 0,
        "bg": PROXMOX_MEDIUM,
        "fg": PROXMOX_LIGHT,
        "activebackground": PROXMOX_ORANGE,
        "activeforeground": "white",
        "bd": 0,
        "relief": "flat",
    }

    menubar = tk.Menu(root, **menu_kwargs)

    file_menu = tk.Menu(menubar, **menu_kwargs)
    file_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)

    menubar.add_command(
        label="Home",
        command=lambda: go_home(root),
    )

    settings_menu = tk.Menu(menubar, **menu_kwargs)
    settings_menu.add_command(
        label="App Settings",
        command=lambda: open_placeholder_view(root, build_app_settings_view, "App Settings"),
    )
    settings_menu.add_command(
        label="Server Settings",
        command=lambda: open_placeholder_view(root, build_server_settings_view, "Server Settings"),
    )
    settings_menu.add_command(
        label="Shell",
        command=lambda: open_placeholder_view(root, build_shell_view, "Shell"),
    )
    menubar.add_cascade(label="Settings", menu=settings_menu)

    vm_menu = tk.Menu(menubar, **menu_kwargs)
    vm_menu.add_command(
        label="Add a virtual machine",
        command=lambda: open_placeholder_view(root, build_add_vm_view, "Add a Virtual Machine"),
    )
    vm_menu.add_command(
        label="Manage virtual machines",
        command=lambda: open_placeholder_view(root, build_manage_vms_view, "Manage Virtual Machines"),
    )
    menubar.add_cascade(label="Virtual Machines", menu=vm_menu)

    container_menu = tk.Menu(menubar, **menu_kwargs)
    container_menu.add_command(
        label="Add a Container",
        command=lambda: open_placeholder_view(root, build_add_container_view, "Add a Container"),
    )
    container_menu.add_command(
        label="Manage Containers",
        command=lambda: open_placeholder_view(
            root, build_manage_containers_view, "Manage Containers"
        ),
    )
    menubar.add_cascade(label="Containers", menu=container_menu)

    root.config(menu=menubar)


def main() -> None:
    root = create_root_window()
    store = AccountStore()
    root.account_store = store  # type: ignore[attr-defined]
    setup_menu(root)

    def start_app() -> None:
        account = store.get_default_account()
        if account is None:
            show_setup_wizard(root, store)
        else:
            root.app_state["account"] = account  # type: ignore[index]
            go_home(root)

    root.after(0, start_app)
    root.mainloop()


if __name__ == "__main__":
    main()

