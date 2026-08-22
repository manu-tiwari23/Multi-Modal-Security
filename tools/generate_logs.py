#!/usr/bin/env python3
"""
Synthetic syslog generator for MMS development and testing.

Generates realistic-looking syslog lines covering the event types the SOC
normaliser understands:

  - SSH authentication failures / successes / invalid-user attempts
  - Firewall blocks (UFW style)
  - Sudo commands
  - Session open/close
  - Generic system errors

Usage::

    # Generate 50 events and write to the default data/raw_logs/sample.log
    python tools/generate_logs.py

    # Generate 200 events to a custom file
    python tools/generate_logs.py --count 200 --output data/raw_logs/custom.log

    # Continuous mode — append one event every 1-3 seconds (Ctrl-C to stop)
    python tools/generate_logs.py --continuous
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Pools of realistic values
# ---------------------------------------------------------------------------

_HOSTS = [
    "webserver01", "webserver02", "db-primary", "db-replica",
    "jumpbox", "mail-gw", "fileserver", "vpn-gateway",
    "k8s-worker-1", "k8s-worker-2", "monitoring",
]

_USERS_VALID = ["admin", "deploy", "alice", "bob", "charlie", "sysop", "jenkins"]
_USERS_INVALID = ["root", "test", "guest", "user", "postgres", "oracle", "ftpuser"]

_ATTACKER_IPS = [
    "185.220.101.42", "45.155.205.233", "193.56.29.100",
    "91.240.118.73", "103.75.201.15", "194.26.192.64",
    "80.82.77.139", "162.142.125.44", "71.6.165.200",
]

_INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.2.50", "192.168.1.100",
    "10.0.3.25", "172.16.0.5",
]

_PROCESSES = {
    "ssh": "sshd",
    "firewall": "kernel",
    "sudo": "sudo",
    "session": "systemd-logind",
    "error": "systemd",
}


# ---------------------------------------------------------------------------
# Event generators — each returns a (process, message) tuple
# ---------------------------------------------------------------------------

def _ssh_auth_failure() -> tuple[str, str]:
    ip = random.choice(_ATTACKER_IPS)
    user = random.choice(_USERS_INVALID + _USERS_VALID)
    port = random.randint(40000, 65535)
    return "sshd", f"Failed password for {'invalid user ' if user in _USERS_INVALID else ''}{user} from {ip} port {port} ssh2"


def _ssh_auth_success() -> tuple[str, str]:
    ip = random.choice(_INTERNAL_IPS)
    user = random.choice(_USERS_VALID)
    port = random.randint(40000, 65535)
    return "sshd", f"Accepted publickey for {user} from {ip} port {port} ssh2"


def _ssh_invalid_user() -> tuple[str, str]:
    ip = random.choice(_ATTACKER_IPS)
    user = random.choice(_USERS_INVALID)
    return "sshd", f"Invalid user {user} from {ip} port {random.randint(40000, 65535)}"


def _firewall_block() -> tuple[str, str]:
    src = random.choice(_ATTACKER_IPS)
    dst = random.choice(_INTERNAL_IPS)
    dpt = random.choice([22, 23, 80, 443, 445, 3389, 5432, 8080, 8443])
    return "kernel", f"[UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={src} DST={dst} PROTO=TCP SPT={random.randint(1024, 65535)} DPT={dpt}"


def _sudo_command() -> tuple[str, str]:
    user = random.choice(_USERS_VALID)
    cmd = random.choice([
        "/usr/bin/systemctl restart nginx",
        "/usr/bin/apt update",
        "/bin/cat /etc/shadow",
        "/usr/sbin/tcpdump -i eth0",
        "/usr/bin/docker ps",
    ])
    return "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


def _session_open() -> tuple[str, str]:
    user = random.choice(_USERS_VALID)
    return "systemd-logind", f"New session 42 of user {user}."


def _session_close() -> tuple[str, str]:
    user = random.choice(_USERS_VALID)
    return "systemd-logind", f"session closed for user {user}"


def _system_error() -> tuple[str, str]:
    errors = [
        "Failed to start Docker Application Container Engine.",
        "nginx.service: Main process exited, code=exited, status=1/FAILURE",
        "Out of memory: Killed process 12345 (java) total-vm:2048000kB",
        "EXT4-fs error (device sda1): ext4_lookup: deleted inode referenced",
        "CRITICAL: disk /dev/sdb1 is 98% full",
    ]
    return "systemd", random.choice(errors)


# Weighted distribution — more failures than successes for realism
_GENERATORS = [
    (_ssh_auth_failure, 30),
    (_ssh_auth_success, 10),
    (_ssh_invalid_user, 15),
    (_firewall_block, 20),
    (_sudo_command, 8),
    (_session_open, 5),
    (_session_close, 5),
    (_system_error, 7),
]

_WEIGHTED_GENERATORS = []
for gen, weight in _GENERATORS:
    _WEIGHTED_GENERATORS.extend([gen] * weight)


def generate_syslog_line() -> str:
    """Generate a single realistic syslog line."""
    generator = random.choice(_WEIGHTED_GENERATORS)
    process, message = generator()
    host = random.choice(_HOSTS)
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 65535)
    return f"{ts} {host} {process}[{pid}]: {message}"


def generate_batch(count: int) -> list[str]:
    """Generate *count* syslog lines."""
    return [generate_syslog_line() for _ in range(count)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic syslog data for MMS")
    parser.add_argument("--count", type=int, default=50, help="Number of events to generate (default: 50)")
    parser.add_argument("--output", type=str, default="data/raw_logs/sample.log", help="Output file path")
    parser.add_argument("--continuous", action="store_true", help="Continuous mode — keep appending events")
    parser.add_argument("--interval-min", type=float, default=0.5, help="Min seconds between events in continuous mode")
    parser.add_argument("--interval-max", type=float, default=3.0, help="Max seconds between events in continuous mode")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    if args.continuous:
        print(f"Continuous mode — appending to {output}  (Ctrl-C to stop)")
        try:
            with open(output, "a", encoding="utf-8") as fh:
                total = 0
                while True:
                    line = generate_syslog_line()
                    fh.write(line + "\n")
                    fh.flush()
                    total += 1
                    print(f"\r  Generated {total} events", end="", flush=True)
                    time.sleep(random.uniform(args.interval_min, args.interval_max))
        except KeyboardInterrupt:
            print(f"\nStopped after {total} events.")
    else:
        lines = generate_batch(args.count)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"Wrote {len(lines)} events to {output}")


if __name__ == "__main__":
    main()
