from __future__ import annotations

import ipaddress
import socket

import psutil


def get_active_ipv4_interface() -> tuple[str, str]:
    gws = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addresses in gws.items():
        if name not in stats or not stats[name].isup:
            continue
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return name, addr.address
    raise RuntimeError("Nenhuma interface IPv4 ativa encontrada")


def infer_local_subnet() -> str:
    _, ip = get_active_ipv4_interface()
    netmask = "255.255.255.0"
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip and addr.netmask:
                netmask = addr.netmask
                break
    network = ipaddress.IPv4Network((ip, netmask), strict=False)
    return str(network)


def compute_gateway_candidates(subnet: str) -> set[str]:
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(net.hosts())
    candidates: set[str] = set()
    if hosts:
        candidates.add(str(hosts[0]))
        if len(hosts) > 1:
            candidates.add(str(hosts[-1]))
    return candidates
