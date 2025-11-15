import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None

try:
    import pyte
except Exception:  # pragma: no cover
    pyte = None

from theme import PROXMOX_DARK, PROXMOX_LIGHT, PROXMOX_ORANGE


class ShellView(tk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent, bg=PROXMOX_DARK)
        self.root = self.winfo_toplevel()
        self.account = getattr(self.root, "app_state", {}).get("account")
        self.proxmox = (self.account or {}).get("proxmox", {}) if self.account else {}
        self.output_queue: queue.Queue = queue.Queue()
        self.reader_thread: threading.Thread | None = None
        self.ssh_client: "paramiko.SSHClient | None" = None
        self.channel = None
        self.running = False
        self.screen_cols = 160
        self.screen_rows = 40
        self.screen: pyte.Screen | None = None
        self.stream: pyte.Stream | None = None
        self.current_screen_text = ""
        self.log_var = tk.StringVar(value="Ready")

        self._build_ui()

    def _build_ui(self) -> None:
        header = tk.Label(
            self,
            text="Proxmox Shell",
            font=("Segoe UI", 24, "bold"),
            fg=PROXMOX_ORANGE,
            bg=PROXMOX_DARK,
        )
        header.pack(anchor=tk.W, pady=(30, 10), padx=30)

        if paramiko is None:
            tk.Label(
                self,
                text=(
                    "Paramiko is not installed. Please run `pip install paramiko` "
                    "to enable shell access."
                ),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
                wraplength=800,
                justify=tk.LEFT,
            ).pack(fill=tk.X, padx=30, pady=10)
            return

        if pyte is None:
            tk.Label(
                self,
                text=(
                    "Pyte terminal emulator is not installed. "
                    "Please run `pip install pyte` to enable shell access."
                ),
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
                wraplength=800,
                justify=tk.LEFT,
            ).pack(fill=tk.X, padx=30, pady=10)
            return

        if not self.proxmox:
            tk.Label(
                self,
                text="No Proxmox credentials available. Please configure your account first.",
                fg=PROXMOX_LIGHT,
                bg=PROXMOX_DARK,
            ).pack(pady=20)
            return

        info = tk.Label(
            self,
            text=f"Host: {self.proxmox.get('host', '')}   User: {self.proxmox.get('username', '')}",
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            font=("Segoe UI", 11),
        )
        info.pack(anchor=tk.W, padx=30)

        button_row = tk.Frame(self, bg=PROXMOX_DARK)
        button_row.pack(fill=tk.X, padx=30, pady=(15, 5))

        self.connect_btn = tk.Button(
            button_row,
            text="Connect",
            command=self.connect,
            bg=PROXMOX_ORANGE,
            fg="white",
            activebackground="#ff8126",
            relief="flat",
            padx=16,
            pady=6,
        )
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.disconnect_btn = tk.Button(
            button_row,
            text="Disconnect",
            command=self.disconnect,
            state=tk.DISABLED,
            bg="#3a414d",
            fg=PROXMOX_LIGHT,
            activebackground="#4a525f",
            relief="flat",
            padx=16,
            pady=6,
        )
        self.disconnect_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.upgrade_btn = tk.Button(
            button_row,
            text="Run apt-get update && dist-upgrade",
            command=self.run_upgrade,
            state=tk.DISABLED,
            bg="#2f3640",
            fg=PROXMOX_LIGHT,
            activebackground="#3a414d",
            relief="flat",
            padx=16,
            pady=6,
        )
        self.upgrade_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.status_var = tk.StringVar(value="Disconnected")
        status = tk.Label(
            self,
            textvariable=self.status_var,
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            anchor="w",
        )
        status.pack(fill=tk.X, padx=30)

        log_label = tk.Label(
            self,
            textvariable=self.log_var,
            fg=PROXMOX_LIGHT,
            bg=PROXMOX_DARK,
            anchor="w",
            font=("Segoe UI", 10),
        )
        log_label.pack(fill=tk.X, padx=30)

        self.terminal = tk.Text(
            self,
            bg="#111317",
            fg=PROXMOX_LIGHT,
            insertbackground=PROXMOX_LIGHT,
            font=("Consolas", 11),
            wrap=tk.NONE,
        )
        self.terminal.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        self.terminal.configure(state=tk.DISABLED)
        self.terminal.bind("<Key>", self._on_keypress)
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.terminal.bind(sequence, self._on_terminal_scroll)
        self.terminal.bind("<Shift-MouseWheel>", self._on_terminal_scroll)

        self.screen = pyte.Screen(self.screen_cols, self.screen_rows)
        self.stream = pyte.Stream(self.screen)
        self.after(100, self._update_output)

    def log(self, message: str) -> None:
        self.output_queue.put(("log", message))

    def connect(self) -> None:
        if not paramiko or self.running:
            return
        raw_host = (self.proxmox.get("host") or "").strip()
        username = self.proxmox.get("username")
        ssh_username_override = self.proxmox.get("ssh_username")
        password = self.proxmox.get("password")
        ssh_port_override = self.proxmox.get("ssh_port")
        if not all([raw_host, username, password]):
            messagebox.showerror("Error", "Missing Proxmox SSH credentials.")
            return

        host = raw_host
        port = 22
        lowered = raw_host.lower()
        if lowered.startswith(("http://", "https://")):
            parsed = urlparse(raw_host)
            host = parsed.hostname or raw_host
            # If the host was stored as an HTTP(S) API URL, default SSH to 22.
            port = 22
        elif ":" in raw_host:
            parts = raw_host.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 22

        if ssh_port_override:
            try:
                port = int(str(ssh_port_override).strip())
            except ValueError:
                self.log(f"Invalid ssh_port value '{ssh_port_override}', falling back to 22.")
                port = 22

        if not host:
            messagebox.showerror("Error", "Unable to determine SSH host. Check your Proxmox settings.")
            return

        ssh_username = ssh_username_override or username or ""
        if "@" in ssh_username and not ssh_username_override:
            ssh_username = ssh_username.split("@", 1)[0]
            self.log(
                "Note: Using local system user "
                f"'{ssh_username}' for SSH (derived from API username)."
            )

        if not ssh_username:
            messagebox.showerror("Error", "Missing SSH username.")
            return

        self.log(f"Opening SSH connection to {host}:{port} as {ssh_username} ...")

        self.status_var.set("Connecting...")
        self.connect_btn.config(state=tk.DISABLED)

        def worker() -> None:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=host,
                    port=port,
                    username=ssh_username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=10,
                )
                channel = client.invoke_shell(
                    width=self.screen_cols,
                    height=self.screen_rows,
                    term="xterm-256color",
                )
                channel.set_combine_stderr(True)
                channel.settimeout(0.1)
                self.ssh_client = client
                self.channel = channel
                self.running = True
                self.log("Connected. You now have an interactive shell.")
                self.root.after(0, self._on_connected)
                self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
                self.reader_thread.start()
            except Exception as exc:
                self.ssh_client = None
                self.channel = None
                self.running = False
                self.log(f"Connection failed: {exc}")
                self.root.after(
                    0,
                    lambda: (
                        self.status_var.set("Connection failed"),
                        self.connect_btn.config(state=tk.NORMAL),
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def _on_connected(self) -> None:
        self.status_var.set("Connected")
        self.disconnect_btn.config(state=tk.NORMAL)
        self.upgrade_btn.config(state=tk.NORMAL)

    def disconnect(self) -> None:
        self.running = False
        if self.channel:
            try:
                self.channel.close()
            except Exception:
                pass
            self.channel = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
        self.status_var.set("Disconnected")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.upgrade_btn.config(state=tk.DISABLED)
        self.log("Disconnected from shell.")

    def _reader_loop(self) -> None:
        while self.running and self.channel is not None:
            try:
                if self.channel.recv_ready():
                    data = self.channel.recv(4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="ignore")
                    if self.stream:
                        self.stream.feed(text)
                        # copy display to avoid mutation
                        display = list(self.screen.display) if self.screen else []
                        self.output_queue.put(("screen", display))
                else:
                    time.sleep(0.05)
            except Exception:
                break
        self.running = False
        self.output_queue.put(("log", "[Connection closed]"))
        self.root.after(
            0,
            lambda: (
                self.disconnect_btn.config(state=tk.DISABLED),
                self.upgrade_btn.config(state=tk.DISABLED),
                self.connect_btn.config(state=tk.NORMAL),
                self.status_var.set("Disconnected"),
            ),
        )

    def _update_output(self) -> None:
        render_needed = False
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "log":
                    self.log_var.set(str(payload))
                elif kind == "screen":
                    self.current_screen_text = "\n".join(payload)
                    render_needed = True
        except queue.Empty:
            pass

        if render_needed:
            self.terminal.configure(state=tk.NORMAL)
            self.terminal.delete("1.0", tk.END)
            self.terminal.insert("1.0", self.current_screen_text)
            self.terminal.configure(state=tk.DISABLED)

        self.after(100, self._update_output)

    def _on_keypress(self, event: tk.Event) -> str:
        if not self.channel or not self.running:
            return "break"

        char = event.char
        if event.keysym == "Return":
            self.channel.send("\r")
        elif event.keysym == "BackSpace":
            self.channel.send("\x7f")
        elif event.keysym == "Escape":
            self.channel.send("\x1b")
        elif event.keysym == "Tab":
            self.channel.send("\t")
        elif event.state & 0x4 and event.keysym.lower() == "c":
            self.channel.send("\x03")
        elif char:
            self.channel.send(char)
        return "break"

    def _on_terminal_scroll(self, event: tk.Event) -> str:
        if event.num == 4 or event.delta > 0:
            self.terminal.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.terminal.yview_scroll(1, "units")
        return "break"

    def run_upgrade(self) -> None:
        if not self.channel or not self.running:
            messagebox.showinfo("Shell", "Please connect to the shell first.")
            return
        self.log("Executing: apt-get update && apt-get dist-upgrade -y")
        try:
            self.channel.send("apt-get update && apt-get dist-upgrade -y\n")
        except Exception as exc:
            self.log(f"Failed to send command: {exc}")


def build_view(parent: tk.Widget) -> tk.Frame:
    return ShellView(parent)
