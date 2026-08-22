from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import PortResult


DEFAULT_PORTS = (102,)
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_rfc1918(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in RFC1918)


def _expand_token(token: str, allow_public: bool, public_explicit_only: bool = True) -> list[str]:
    token = token.strip()
    if not token:
        return []
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.version != 4:
            raise ValueError("IPv6 CIDR scanning is not supported in this release")
        # Only RFC1918 CIDRs may be expanded. This deliberately refuses public,
        # documentation, shared, loopback, link-local, multicast, and reserved blocks.
        if not all(is_rfc1918(h) for h in (net.network_address, net.broadcast_address)):
            if public_explicit_only:
                raise ValueError("only RFC1918 CIDR expansion is allowed; supply authorized non-RFC1918 IPs individually")
        hosts = [str(h) for h in net.hosts()]
    else:
        ip = ipaddress.ip_address(token)
        if ip.version != 4:
            raise ValueError("IPv6 targets are not supported in this release")
        hosts = [str(ip)]

    for host in hosts:
        ip = ipaddress.ip_address(host)
        if not is_rfc1918(ip) and not allow_public:
            raise ValueError(
                f"non-RFC1918 target {host} refused. Use --allow-public only for IPs you own or are authorized to test"
            )
    return hosts


def expand_targets(spec: str, allow_public: bool, max_hosts: int) -> list[str]:
    targets: list[str] = []
    seen = set()
    for token in spec.split(","):
        for host in _expand_token(token, allow_public=allow_public):
            if host not in seen:
                seen.add(host)
                targets.append(host)
            if len(targets) > max_hosts:
                raise ValueError(f"target set exceeds safety limit of {max_hosts} hosts")
    return targets


def tcp_check(host: str, port: int, timeout: float) -> PortResult:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - started) * 1000.0
            return PortResult(port=port, open=True, latency_ms=round(latency, 2))
    except (socket.timeout, TimeoutError) as e:
        return PortResult(port=port, open=False, error=e.__class__.__name__)
    except OSError as e:
        return PortResult(port=port, open=False, error=str(e))


def scan_host(host: str, ports: tuple[int, ...], timeout: float) -> list[PortResult]:
    return [tcp_check(host, p, timeout) for p in ports]


def scan_many(targets: list[str], ports: tuple[int, ...], timeout: float, workers: int = 16):
    workers = max(1, min(workers, 32))
    results: dict[str, list[PortResult]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, host, ports, timeout): host for host in targets}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                results[host] = fut.result()
            except Exception as e:
                results[host] = [PortResult(port=p, open=False, error=f"scan error: {e}") for p in ports]
    return results
