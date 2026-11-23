"""TShark / Wireshark capture adapter skeleton — optional after Nmap."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class TsharkAdapter(SkeletonAdapter):
    scanner_id = "tshark"
    display_name = "TShark"
    description = "Packet capture (often needs elevation / Npcap)."
    capabilities = frozenset({Capability.network})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("tshark",)
    accepted_target_types = frozenset(
        {ScopeEntryType.ip, ScopeEntryType.cidr, ScopeEntryType.domain}
    )
    install_hint = "Install Wireshark/TShark; capture may require admin rights."
