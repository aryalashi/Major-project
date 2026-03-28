"""
normalization.py
----------------
Packet Normalization Layer for NIDS

Converts raw Scapy packets into a flat, canonical dictionary schema.
Protocol routing is determined EXCLUSIVELY by IP.proto field — never
by Scapy layer-presence checks — preventing cross-protocol false positives
caused by encapsulated headers (e.g. TCP headers inside ICMP error payloads).

Canonical Schema
----------------
{
    "src":        str,    # Source IP address
    "dst":        str,    # Destination IP address
    "protocol":   str,    # "TCP" | "UDP" | "ICMP" | "OTHER"
    "src_port":   int|None,  # TCP/UDP only; None for ICMP
    "dst_port":   int|None,  # TCP/UDP only; None for ICMP
    "flags":      str|None,  # TCP only (e.g. "S", "SA"); None for UDP/ICMP
    "icmp_type":  int|None,  # ICMP only; None for TCP/UDP
    "icmp_code":  int|None,  # ICMP only; None for TCP/UDP
    "size":       int,    # Total packet size in bytes
    "timestamp":  float,  # Unix capture timestamp
}

IP Protocol Numbers (IANA)
--------------------------
  1  = ICMP
  6  = TCP
  17 = UDP

Design Notes
------------
- Uses packet[IP].proto as the single source of truth for protocol type.
- NEVER uses Scapy's `TCP in packet` / `UDP in packet` / `ICMP in packet`
  for protocol classification — these traverse the full packet tree and
  can match encapsulated layer headers inside ICMP error payloads.
- Fields irrelevant to the identified protocol are always set to None.
- Returns None for non-IP packets or unsupported protocols so the caller
  can discard them without branching logic.
"""

import logging
import time
from typing import Optional

logger = logging.getLogger("Normalization")

# ── IANA IP Protocol Numbers ────────────────────────────────────────────────

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# ── TCP Flag Bitmask Map ─────────────────────────────────────────────────────

_TCP_FLAG_MAP = [
    (0x001, "F"),   # FIN
    (0x002, "S"),   # SYN
    (0x004, "R"),   # RST
    (0x008, "P"),   # PSH
    (0x010, "A"),   # ACK
    (0x020, "U"),   # URG
    (0x040, "E"),   # ECE
    (0x080, "C"),   # CWR
]


def _decode_tcp_flags(flag_int: int) -> str:
    """Convert integer TCP flags to a canonical flag string (e.g. 'SA', 'S')."""
    return "".join(ch for bit, ch in _TCP_FLAG_MAP if flag_int & bit)


# ── Public API ───────────────────────────────────────────────────────────────

def normalize_packet(raw_pkt) -> Optional[dict]:
    """
    Normalize a raw Scapy packet into the canonical NIDS packet schema.

    Args:
        raw_pkt: A raw Scapy packet object from sniff().

    Returns:
        A canonical packet dict, or None if the packet should be discarded
        (non-IP, unsupported protocol, or missing required layers).

    Protocol Routing
    ----------------
    Classification is done via packet[IP].proto exclusively:
        proto=1  → ICMP  (ports=None, flags=None)
        proto=6  → TCP   (icmp_type=None, icmp_code=None)
        proto=17 → UDP   (flags=None, icmp_type=None, icmp_code=None)
        other    → None  (packet discarded)

    This prevents false positives from Scapy's deep-parse operator which
    would otherwise detect TCP headers encapsulated inside ICMP payloads.
    """
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        
        if IP not in raw_pkt:
            return None
        
        ip_layer = raw_pkt[IP]
        base = {
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "size": len(raw_pkt),
            "timestamp": time.time() if 'time' in dir(raw_pkt) else 0,
        }
        
        # Exclusive protocol routing based on IP.proto
        if ip_layer.proto == PROTO_TCP:
            return _normalize_tcp(raw_pkt, ip_layer, base)
        elif ip_layer.proto == PROTO_UDP:
            return _normalize_udp(raw_pkt, ip_layer, base)
        elif ip_layer.proto == PROTO_ICMP:
            return _normalize_icmp(raw_pkt, ip_layer, base)
        else:
            # Unsupported protocol
            return None

    except Exception as exc:
        logger.error(f"Normalization error: {exc}")
        return None


# ── Protocol-Specific Normalizers ────────────────────────────────────────────

def _extract_payload(raw_pkt) -> Optional[bytes]:
    """Extract raw payload bytes from packet."""
    try:
        from scapy.all import Raw
        if Raw in raw_pkt:
            return bytes(raw_pkt[Raw].load)
    except Exception:
        pass
    return None

def _normalize_tcp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """Normalize a TCP packet."""
    try:
        from scapy.all import TCP
        if TCP not in raw_pkt:
            return None
        
        tcp_layer = raw_pkt[TCP]
        
        return {
            **base,
            "protocol": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "flags": _decode_tcp_flags(tcp_layer.flags),
            "icmp_type": None,
            "icmp_code": None,
        }
    except Exception as e:
        logger.error(f"TCP normalization error: {e}")
        return None


def _normalize_udp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """Normalize a UDP packet."""
    try:
        from scapy.all import UDP
        if UDP not in raw_pkt:
            return None
        
        udp_layer = raw_pkt[UDP]
        
        return {
            **base,
            "protocol": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "flags": None,
            "icmp_type": None,
            "icmp_code": None,
        }
    except Exception as e:
        logger.error(f"UDP normalization error: {e}")
        return None


def _normalize_icmp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """Normalize an ICMP packet."""
    try:
        from scapy.all import ICMP
        if ICMP not in raw_pkt:
            return None
        
        icmp_layer = raw_pkt[ICMP]
        
        return {
            **base,
            "protocol": "ICMP",
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "icmp_type": icmp_layer.type,
            "icmp_code": icmp_layer.code,
        }
    except Exception as e:
        logger.error(f"ICMP normalization error: {e}")
        return None
