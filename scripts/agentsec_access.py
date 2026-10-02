#!/usr/bin/env python3
"""Learner access facts for local and remote AgentSec installs.

This file does not open ports, change firewalls, or print secrets.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import urllib.request

LOOPBACK = frozenset({"127.0.0.1", "[::1]"})
PUBLIC_ANY = frozenset({"0.0.0.0", "*", "[::]"})
LEARNER_PORTS = (8000, 5001)
PRIVATE_PORTS = (5000, 8088, 4317, 4318, 11434)
TOKEN = re.compile(r"(?P<host>\*|0\.0\.0\.0|\[::\]|\[::1\]|127\.0\.0\.1):(?P<port>\d+)\b")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$")
ACADEMY_PATH = "/en-US/app/agentsec/ws_agentsec_home"


def parse_listeners(text: str) -> dict[int, set[str]]:
    found: dict[int, set[str]] = {}
    for match in TOKEN.finditer(text):
        port = int(match.group("port"))
        found.setdefault(port, set()).add(match.group("host"))
    return found


def _kinds(hosts: set[str]) -> set[str]:
    kinds = set()
    for host in hosts:
        if host in LOOPBACK:
            kinds.add("loopback")
        elif host in PUBLIC_ANY:
            kinds.add("public")
        else:
            kinds.add("other")
    return kinds


def evaluate(text: str, mode: str) -> dict[str, object]:
    """Return a listener verdict. mode is local or remote."""
    listeners = parse_listeners(text)
    problems: list[str] = []
    academy_public = "public" in _kinds(listeners.get(8000, set()))
    attack_public = "public" in _kinds(listeners.get(5001, set()))
    for port in PRIVATE_PORTS:
        if "public" in _kinds(listeners.get(port, set())):
            problems.append(f"private port {port} has a public listener")
    if mode == "remote":
        if not academy_public:
            problems.append("Academy port 8000 is not a public listener")
        if not attack_public:
            problems.append("Attack Service port 5001 is not a public listener")
    elif mode == "local":
        if academy_public:
            problems.append("Academy port 8000 is public in local mode")
        if attack_public:
            problems.append("Attack Service port 5001 is public in local mode")
    return {
        "ok": not problems,
        "problems": problems,
        "academy_public": academy_public,
        "attack_public": attack_public,
        "listeners": {port: sorted(hosts) for port, hosts in sorted(listeners.items())},
    }


def capture_listener_text() -> str | None:
    if shutil.which("ss"):
        completed = subprocess.run(
            ["ss", "-lnt"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout
    if shutil.which("lsof"):
        completed = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0:
            return completed.stdout
    return None


def valid_public_host(value: str) -> str:
    candidate = value.strip()
    if not candidate or not HOST_RE.fullmatch(candidate):
        return ""
    if candidate.lower() in {"localhost", "127.0.0.1"}:
        return ""
    return candidate


def _private_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return False
    octets = [int(part) for part in parts]
    if any(octet > 255 for octet in octets):
        return True
    if octets[0] in {10, 127}:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def _read_url(url: str, headers: dict[str, str] | None = None, timeout: float = 1.0) -> str:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(256).decode("utf-8", errors="replace").strip()
    return body.split()[0] if body else ""


def metadata_public_ipv4() -> str:
    """Query link-local cloud metadata only. Never call a public IP website."""
    token = ""
    try:
        request = urllib.request.Request(
            "http://169.254.169.169/latest/api/token",
            data=b"",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            method="PUT",
        )
        with urllib.request.urlopen(request, timeout=1.0) as response:
            token = response.read(256).decode("utf-8", errors="replace").strip()
    except Exception:
        token = ""
    if token:
        try:
            ip = _read_url(
                "http://169.254.169.169/latest/meta-data/public-ipv4",
                headers={"X-aws-ec2-metadata-token": token},
            )
            if ip and not _private_ipv4(ip) and valid_public_host(ip):
                return ip
        except Exception:
            pass
    for url, headers in (
        (
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text",
            {"Metadata": "true"},
        ),
        (
            "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
            {"Metadata-Flavor": "Google"},
        ),
    ):
        try:
            ip = _read_url(url, headers=headers)
        except Exception:
            continue
        if ip and not _private_ipv4(ip) and valid_public_host(ip):
            return ip
    return ""


def resolve_public_host(allow_metadata: bool) -> tuple[str, str]:
    configured = valid_public_host(os.environ.get("AGENTSEC_PUBLIC_HOST", ""))
    if configured:
        return configured, "AGENTSEC_PUBLIC_HOST"
    if not allow_metadata:
        return "", ""
    discovered = metadata_public_ipv4()
    if discovered:
        return discovered, "cloud-metadata"
    return "", ""


def learner_urls(host: str) -> tuple[str, str]:
    if host:
        return (
            f"http://{host}:8000{ACADEMY_PATH}",
            f"http://{host}:5001",
        )
    return (
        f"http://<your-server-public-ip>:8000{ACADEMY_PATH}",
        "http://<your-server-public-ip>:5001",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentSec listener and learner URL helper")
    sub = parser.add_subparsers(dest="command", required=True)
    classify = sub.add_parser("classify")
    classify.add_argument("--mode", choices=("local", "remote"), required=True)
    classify.add_argument("--text-file")
    host = sub.add_parser("public-host")
    host.add_argument("--metadata", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "public-host":
        value, _source = resolve_public_host(args.metadata)
        if value:
            print(value)
        return 0
    if args.text_file:
        text = open(args.text_file, encoding="utf-8").read()
    else:
        text = capture_listener_text()
        if text is None:
            print("listeners: NOT MEASURED", file=sys.stderr)
            return 2
    result = evaluate(text, args.mode)
    if result["ok"]:
        print(f"listeners: OK mode={args.mode}")
        return 0
    for problem in result["problems"]:
        print(f"listeners: {problem}", file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
