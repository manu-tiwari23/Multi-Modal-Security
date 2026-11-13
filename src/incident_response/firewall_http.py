"""Explicit HTTP firewall adapter; called only after durable analyst approval."""
import hashlib
import ipaddress
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict
from typing import Literal

from .executor import ActionBackend
from .models import ActionResult, ActionType


class FirewallConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action_id: str
    status: Literal["applied", "rejected"]
    action_type: Literal["block_ip", "block_egress"]
    ip: str


class HttpFirewallBackend(ActionBackend):
    name = "http_firewall"
    supported_actions = frozenset({ActionType.BLOCK_IP, ActionType.BLOCK_EGRESS})

    def __init__(self, endpoint, token, timeout=5, transport=None):
        parts = urlsplit(endpoint)
        if not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("Firewall endpoint must be a configured URL without credentials, query or fragment")
        loopback = parts.hostname == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            pass
        if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
            raise ValueError("Firewall endpoint requires HTTPS, except a loopback test adapter")
        if not token or not token.strip():
            raise ValueError("Firewall API token is required")
        self.endpoint, self.token, self.timeout, self.transport = endpoint, token, timeout, transport
        self.configuration_id = hashlib.sha256(endpoint.encode()).hexdigest()

    def execute(self, action):
        if action.action_type not in self.supported_actions:
            raise ValueError("Unsupported firewall action")
        address = str(ipaddress.ip_address(action.target_entity.get("ip", "")))
        body = {"action_id": action.action_id, "action_type": action.action_type.value, "ip": address}
        with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False, transport=self.transport) as client:
            with client.stream("POST", self.endpoint, headers={"Authorization": f"Bearer {self.token}",
                    "Idempotency-Key": action.action_id, "Accept": "application/json"}, json=body) as response:
                if response.status_code != 200:
                    return ActionResult(action_id=action.action_id, success=False, backend=self.name,
                        message=f"Firewall did not confirm application (HTTP {response.status_code}). Inspect the backend before further action.")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 16384:
                        raise ValueError("Firewall response exceeds the confirmation limit")
        confirmation = FirewallConfirmation.model_validate_json(bytes(raw))
        if confirmation.action_id != action.action_id or confirmation.action_type != action.action_type.value or confirmation.ip != address:
            raise ValueError("Firewall confirmation does not match the approved action")
        applied = confirmation.status == "applied"
        return ActionResult(action_id=action.action_id, success=applied, backend=self.name,
            message="Firewall adapter confirmed application." if applied else "Firewall adapter rejected the action.",
            details={"confirmed_target": address, "adapter_status": confirmation.status})
