from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
import ssl
import urllib3

logger = logging.getLogger(__name__)


class ProxmoxAPIError(Exception):
    """Raised when the Proxmox API returns an error response."""


def _normalize_host(host: str) -> str:
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


@dataclass
class ProxmoxSummary:
    version: dict[str, Any]
    node_name: str | None
    node_status: dict[str, Any] | None
    network: list[dict[str, Any]]
    storage: list[dict[str, Any]]
    vms: list[dict[str, Any]]
    containers: list[dict[str, Any]]

class FingerprintAdapter(HTTPAdapter):
    def __init__(self, fingerprint: str, *args, **kwargs) -> None:
        self.fingerprint = self._normalize_fingerprint(fingerprint)
        super().__init__(*args, **kwargs)

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        tokens = value.replace(":", "").strip().lower()
        return ":".join(tokens[i : i + 2] for i in range(0, len(tokens), 2))

    def init_poolmanager(self, *args, **kwargs) -> None:
        kwargs.setdefault("assert_hostname", False)
        kwargs["assert_fingerprint"] = self.fingerprint
        kwargs["cert_reqs"] = ssl.CERT_NONE
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs.setdefault("assert_hostname", False)
        kwargs["assert_fingerprint"] = self.fingerprint
        kwargs["cert_reqs"] = ssl.CERT_NONE
        return super().proxy_manager_for(*args, **kwargs)


class ProxmoxClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        realm: str | None = None,
        trusted_cert: str | None = None,
        trusted_fingerprint: str | None = None,
    ) -> None:
        self.base_url = _normalize_host(host)
        if realm and "@" not in username:
            username = f"{username}@{realm}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.trusted_cert = trusted_cert
        self.trusted_fingerprint = trusted_fingerprint
        self.session = requests.Session()
        self._use_fingerprint = bool(trusted_fingerprint)
        if self._use_fingerprint:
            adapter = FingerprintAdapter(trusted_fingerprint)
            self.session.mount("https://", adapter)
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ticket: str | None = None
        self.csrf_token: str | None = None
        self._authenticate()

    def close(self) -> None:
        self.session.close()

    def _authenticate(self) -> None:
        payload = {"username": self.username, "password": self.password}
        verify_target: bool | str = False if self._use_fingerprint else (self.trusted_cert or self.verify_ssl)
        response = self.session.post(
            f"{self.base_url}/api2/json/access/ticket",
            data=payload,
            verify=verify_target,
            timeout=20,
        )
        data = self._parse_response(response)
        auth = data.get("data", {})
        self.ticket = auth.get("ticket")
        self.csrf_token = auth.get("CSRFPreventionToken")
        if not self.ticket:
            raise ProxmoxAPIError("Authentication failed: missing ticket.")
        self.session.cookies.set("PVEAuthCookie", self.ticket)

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.csrf_token:
            headers["CSRFPreventionToken"] = self.csrf_token
        return headers

    def _parse_response(self, response: requests.Response) -> dict[str, Any]:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise ProxmoxAPIError(f"API request failed: {exc}") from exc
        try:
            return response.json()
        except ValueError as exc:
            raise ProxmoxAPIError("Invalid JSON response from Proxmox API.") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/api2/json/{path.lstrip('/')}"
        verify_target: bool | str = False if self._use_fingerprint else (self.trusted_cert or self.verify_ssl)
        response = self.session.request(
            method,
            url,
            params=params,
            data=data,
            headers=self._headers(),
            verify=verify_target,
            timeout=20,
        )
        return self._parse_response(response)

    def _get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params)

    def get_version(self) -> dict[str, Any]:
        return self._get("version").get("data", {})

    def get_nodes(self) -> list[dict[str, Any]]:
        return self._get("nodes").get("data", [])

    def get_node_status(self, node: str) -> dict[str, Any]:
        return self._get(f"nodes/{node}/status").get("data", {})

    def get_node_network(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/network").get("data", [])

    def get_node_storage(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/storage").get("data", [])

    def get_node_vms(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/qemu").get("data", [])

    def get_vm_config(self, node: str, vmid: int | str) -> dict[str, Any]:
        return self._get(f"nodes/{node}/qemu/{vmid}/config").get("data", {})

    def start_vm(self, node: str, vmid: int | str) -> dict[str, Any]:
        return self._request("POST", f"nodes/{node}/qemu/{vmid}/status/start", data={}).get("data", {})

    def stop_vm(self, node: str, vmid: int | str) -> dict[str, Any]:
        return self._request("POST", f"nodes/{node}/qemu/{vmid}/status/stop", data={}).get("data", {})

    def reboot_vm(self, node: str, vmid: int | str) -> dict[str, Any]:
        return self._request("POST", f"nodes/{node}/qemu/{vmid}/status/reboot", data={}).get("data", {})

    def get_node_containers(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/lxc").get("data", [])

    def get_spice_config(self, node: str, vmid: int | str) -> str:
        resp = self._request("POST", f"nodes/{node}/qemu/{vmid}/spiceproxy", data={})
        data = resp.get("data")
        if isinstance(data, str):
            return data
        # Some API variants might wrap the config differently; fail with a clear message.
        raise ProxmoxAPIError("Unexpected SPICE config format from Proxmox API.")

    def get_vnc_proxy(self, node: str, vmid: int | str) -> dict[str, Any]:
        resp = self._request("POST", f"nodes/{node}/qemu/{vmid}/vncproxy", data={})
        data = resp.get("data") or {}
        if not isinstance(data, dict):
            raise ProxmoxAPIError("Unexpected VNC proxy format from Proxmox API.")
        return data

    def refresh_apt_cache(self, node: str) -> dict[str, Any]:
        return self._request("POST", f"nodes/{node}/apt/update", data={}).get("data", {})

    def list_available_updates(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/apt/update").get("data", [])

    def install_updates(self, node: str, packages: list[str] | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if packages:
            data["packages"] = ",".join(packages)
        return self._request("POST", f"nodes/{node}/apt/update", data=data).get("data", {})

    def upgrade_packages(self, node: str) -> dict[str, Any]:
        # Runs apt dist-upgrade via the API.
        return self._request("POST", f"nodes/{node}/apt/upgrade").get("data", {})

    def get_task_status(self, node: str, upid: str) -> dict[str, Any]:
        encoded = quote(upid, safe="")
        return self._get(f"nodes/{node}/tasks/{encoded}/status").get("data", {})

    def get_task_log(self, node: str, upid: str, start: int = 0) -> list[dict[str, Any]]:
        encoded = quote(upid, safe="")
        params = {"start": start}
        return self._get(f"nodes/{node}/tasks/{encoded}/log", params=params).get("data", [])

    def stop_task(self, node: str, upid: str) -> dict[str, Any]:
        encoded = quote(upid, safe="")
        return self._request("POST", f"nodes/{node}/tasks/{encoded}/status", data={"status": "stop"}).get("data", {})

    # Repository management helpers
    def list_repositories(self, node: str) -> list[dict[str, Any]]:
        return self._get(f"nodes/{node}/apt/repositories").get("data", {}).get("repositories", [])

    def switch_non_subscription_repos(self, node: str) -> dict[str, Any]:
        payload = {
            "standard-repos": "1",
            "pvetest": "0",
            "ceph": "no-subscription",
            "proxmox": "no-subscription",
            "test": "0",
        }
        return self._request("POST", f"nodes/{node}/apt/repositories", data=payload).get("data", {})

    @staticmethod
    def _parse_vm_networks(config: dict[str, Any]) -> list[dict[str, str]]:
        networks: list[dict[str, str]] = []
        for key, value in config.items():
            if not key.startswith("net"):
                continue
            # value format: model=xx:xx:...,bridge=vmbr0,tag=...
            parts = {}
            for segment in str(value).split(","):
                if "=" in segment:
                    k, v = segment.split("=", 1)
                    parts[k.strip()] = v.strip()
            networks.append(
                {
                    "name": key,
                    "model": parts.get("model", "unknown"),
                    "mac": parts.get("macaddr") or parts.get("mac") or parts.get("hwaddr") or "unknown",
                    "bridge": parts.get("bridge", "unknown"),
                    "tag": parts.get("tag", ""),
                    "firewall": parts.get("firewall", ""),
                    "rate": parts.get("rate", ""),
                }
            )
        return networks

    def get_storage_content(self, node: str, storage: str) -> list[dict[str, Any]]:
        """Get content of a storage (ISOs, disk images, etc.)."""
        return self._get(f"nodes/{node}/storage/{storage}/content").get("data", [])

    def get_next_vmid(self) -> int:
        """Get the next available VM ID."""
        result = self._get("cluster/nextid")
        vmid = result.get("data")
        if isinstance(vmid, (int, str)):
            try:
                return int(vmid)
            except ValueError:
                pass
        raise ProxmoxAPIError("Unable to get next VM ID from Proxmox API.")

    def create_vm(self, node: str, vmid: int, config: dict[str, Any]) -> dict[str, Any]:
        """Create a new VM with the given configuration."""
        data = {"vmid": vmid, **config}
        return self._request("POST", f"nodes/{node}/qemu", data=data).get("data", {})

    def fetch_summary(self) -> ProxmoxSummary:
        version = self.get_version()
        nodes = self.get_nodes()
        if not nodes:
            return ProxmoxSummary(version, None, None, [], [], [], [])

        # Pick the first node for now.
        node_name = nodes[0].get("node")
        node_status = self.get_node_status(node_name) if node_name else None
        network = self.get_node_network(node_name) if node_name else []
        storage = self.get_node_storage(node_name) if node_name else []
        vms_raw = self.get_node_vms(node_name) if node_name else []
        vms: list[dict[str, Any]] = []
        for vm in vms_raw:
            vm_copy = vm.copy()
            vmid = vm.get("vmid")
            if node_name and vmid is not None:
                config = self.get_vm_config(node_name, vmid)
                vm_copy["network"] = self._parse_vm_networks(config)
            vms.append(vm_copy)
        containers = self.get_node_containers(node_name) if node_name else []

        return ProxmoxSummary(version, node_name, node_status, network, storage, vms, containers)

