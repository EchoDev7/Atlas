#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
from typing import Iterable


def parse_target_ports(raw: str) -> list[int]:
    values: list[int] = []
    for part in (raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        port = int(token)
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid target port: {port}")
        values.append(port)

    if not values:
        raise ValueError("At least one target port is required")
    return values


def forward_to_targets(sock: socket.socket, payload: bytes, target_host: str, target_ports: Iterable[int]) -> None:
    for target_port in target_ports:
        sock.sendto(payload, (target_host, target_port))


def main() -> None:
    parser = argparse.ArgumentParser(description="DNSTT UDP packet duplication multiplexer")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9000)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-ports", required=True, help="Comma-separated UDP target ports")
    args = parser.parse_args()

    target_ports = parse_target_ports(args.target_ports)
    upstream_endpoints = {(args.target_host, port) for port in target_ports}

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.listen_host, args.listen_port))

    last_vpn_client: tuple[str, int] | None = None

    while True:
        data, source = server.recvfrom(65535)

        if source in upstream_endpoints:
            if last_vpn_client is not None:
                server.sendto(data, last_vpn_client)
            continue

        last_vpn_client = source
        forward_to_targets(server, data, args.target_host, target_ports)


if __name__ == "__main__":
    main()
