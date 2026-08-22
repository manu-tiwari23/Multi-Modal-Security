"""
Deceptive honeypot service and virtual shell emulator.

Provides safe, sandboxed simulation of common Linux shell commands, authentication,
and file downloads without ever executing real host binaries or touching host resources.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Optional

from src.honeypot.models import CommandRecord, FileArtifact, HoneypotSession
from src.honeypot.recorder import SessionRecorder

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Virtual Filesystem & Mock Responses
# ---------------------------------------------------------------------------

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
    "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
    "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
)

FAKE_OS_RELEASE = (
    'NAME="Ubuntu"\n'
    'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
    'ID=ubuntu\n'
    'ID_LIKE=debian\n'
    'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
    'VERSION_ID="22.04"\n'
    'HOME_URL="https://www.ubuntu.com/"\n'
    'SUPPORT_URL="https://help.ubuntu.com/"\n'
    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
)

FAKE_PS = (
    "  PID TTY          TIME CMD\n"
    "    1 ?        00:00:02 systemd\n"
    "  450 ?        00:00:00 systemd-journald\n"
    "  480 ?        00:00:00 cron\n"
    "  520 ?        00:00:00 rsyslogd\n"
    "  600 ?        00:00:01 sshd\n"
    " 1420 ?        00:00:00 nginx\n"
    " 4401 ?        00:00:00 sshd\n"
    " 4405 pts/0    00:00:00 bash\n"
    " 4410 pts/0    00:00:00 ps\n"
)

FAKE_IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
    "        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n"
    "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 12044  bytes 9102432 (9.1 MB)\n"
    "        TX packets 8540  bytes 1204850 (1.2 MB)\n\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
    "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
    "        loop  txqueuelen 1000  (Local Loopback)\n"
)

# ---------------------------------------------------------------------------
# TTP Classification Rules for Shell Commands
# ---------------------------------------------------------------------------

_TTP_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex_pattern, ttp_category, mitre_technique)
    (re.compile(r"\b(uname|whoami|id|hostname|uptime|lscpu|nproc|arch)\b", re.I), "recon", "T1082"),
    (re.compile(r"\b(ifconfig|ip|route|netstat|ss|arp)\b", re.I), "recon", "T1016"),
    (re.compile(r"\b(ps|top|htop|pstree)\b", re.I), "recon", "T1057"),
    (re.compile(r"\b(cat\s+/etc/(passwd|shadow|group)|getent|w|who|last)\b", re.I), "credential_access", "T1087.001"),
    (re.compile(r"\b(wget|curl|tftp|ftpget|fetch)\b", re.I), "download", "T1105"),
    (re.compile(r"\b(chmod|chown|chgrp)\b", re.I), "execution", "T1222.002"),
    (re.compile(r"\b(crontab|systemctl|chkconfig)\b", re.I), "persistence", "T1053.003"),
    (re.compile(r"\b(sudo|su|pkexec|doas)\b", re.I), "privilege_escalation", "T1548.003"),
    (re.compile(r"\b(shred|dd)\b|rm\s+-rf|history\s+-c", re.I), "defense_evasion", "T1070.004"),
    (re.compile(r"\b(ping|traceroute|nmap|masscan|zmap)\b", re.I), "discovery", "T1046"),
    (re.compile(r"\b(bash|sh|zsh|python|perl|ruby)\b|/bin/(bash|sh|zsh)", re.I), "execution", "T1059.004"),
]


class VirtualShell:
    """Safely emulates standard Linux shell commands in a virtual sandbox."""

    def __init__(self, current_user: str = "root", hostname: str = "honeypot-srv") -> None:
        self.current_user = current_user
        self.hostname = hostname
        self.cwd = "/root" if current_user == "root" else f"/home/{current_user}"
        self.history: list[str] = []

    def classify_command(self, cmd_line: str) -> tuple[list[str], list[str]]:
        """Extract TTP categories and MITRE technique IDs from command text."""
        categories: set[str] = set()
        techniques: set[str] = set()

        for pattern, cat, mitre in _TTP_PATTERNS:
            if pattern.search(cmd_line):
                categories.add(cat)
                techniques.add(mitre)

        if not categories:
            categories.add("generic_command")

        return sorted(list(categories)), sorted(list(techniques))

    def execute(self, cmd_line: str) -> tuple[str, int, list[str], list[str]]:
        """Simulate command execution.

        Returns:
            (output_str, return_code, ttp_categories, mitre_techniques)
        """
        raw = cmd_line.strip()
        if not raw:
            return "", 0, [], []

        self.history.append(raw)
        categories, mitre_techs = self.classify_command(raw)

        # Tokenize basic command
        tokens = raw.split()
        cmd = tokens[0].lower() if tokens else ""
        args = tokens[1:] if len(tokens) > 1 else []

        # Handle 'sudo' prefix cleanly
        if cmd == "sudo" and args:
            cmd = args[0].lower()
            args = args[1:]

        # ------------------------------------------------------------------
        # Command Dispatch Table (Simulated Safe Handlers)
        # ------------------------------------------------------------------
        if cmd == "uname":
            if "-a" in args or "-r" in args:
                return "Linux honeypot-srv 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 GNU/Linux\n", 0, categories, mitre_techs
            return "Linux\n", 0, categories, mitre_techs

        elif cmd == "whoami":
            return f"{self.current_user}\n", 0, categories, mitre_techs

        elif cmd == "id":
            if self.current_user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", 0, categories, mitre_techs
            return f"uid=1000({self.current_user}) gid=1000({self.current_user}) groups=1000({self.current_user}),27(sudo)\n", 0, categories, mitre_techs

        elif cmd == "hostname":
            return f"{self.hostname}\n", 0, categories, mitre_techs

        elif cmd == "pwd":
            return f"{self.cwd}\n", 0, categories, mitre_techs

        elif cmd in ("ls", "dir"):
            if self.cwd == "/root":
                return ".bash_history  .bashrc  .profile  .ssh\n", 0, categories, mitre_techs
            return "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n", 0, categories, mitre_techs

        elif cmd == "cd":
            target = args[0] if args else "/root"
            if target == "..":
                self.cwd = "/" if self.cwd.count("/") <= 1 else "/".join(self.cwd.split("/")[:-1])
            elif target.startswith("/"):
                self.cwd = target
            else:
                self.cwd = f"{self.cwd.rstrip('/')}/{target}"
            return "", 0, categories, mitre_techs

        elif cmd == "cat":
            target_file = args[0] if args else ""
            if "passwd" in target_file:
                return FAKE_PASSWD, 0, categories, mitre_techs
            elif "shadow" in target_file:
                if self.current_user == "root":
                    return "root:$6$rounds=4096$vF8...:19600:0:99999:7:::\nadmin:$6$rounds=4096$zT9...:19600:0:99999:7:::\n", 0, categories, mitre_techs
                return "cat: /etc/shadow: Permission denied\n", 1, categories, mitre_techs
            elif "os-release" in target_file or "issue" in target_file:
                return FAKE_OS_RELEASE, 0, categories, mitre_techs
            elif "version" in target_file:
                return "Linux version 5.15.0-89-generic (buildd@lcy02-amd64-077) (gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)) #99-Ubuntu SMP\n", 0, categories, mitre_techs
            return f"cat: {target_file}: No such file or directory\n", 1, categories, mitre_techs

        elif cmd in ("ps", "top"):
            return FAKE_PS, 0, categories, mitre_techs

        elif cmd in ("ifconfig", "ip"):
            return FAKE_IFCONFIG, 0, categories, mitre_techs

        elif cmd in ("wget", "curl"):
            url = args[-1] if args else "http://attacker.com/payload"
            return (
                f"--2026-08-22 14:02:11--  {url}\n"
                f"Resolving attacker host... 203.0.113.88\n"
                f"Connecting to 203.0.113.88:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 45056 (44K) [application/x-executable]\n"
                f"Saving to: 'payload'\n\n"
                f"payload             100%[===================>]  44.00K  --.-KB/s    in 0.05s\n\n"
                f"2026-08-22 14:02:11 (880 KB/s) - 'payload' saved [45056/45056]\n"
            ), 0, categories, mitre_techs

        elif cmd == "chmod":
            return "", 0, categories, mitre_techs

        elif cmd == "history":
            hist_out = "\n".join(f"  {i+1}  {h}" for i, h in enumerate(self.history))
            return f"{hist_out}\n", 0, categories, mitre_techs

        elif cmd == "echo":
            return f"{' '.join(args)}\n", 0, categories, mitre_techs

        elif cmd in ("exit", "logout", "quit"):
            return "logout\n", 0, ["session_close"], ["T1078"]

        else:
            return f"bash: {cmd}: command not found\n", 127, categories, mitre_techs


class DeceptionService:
    """High-level deceptive service manager tying virtual shell to the session recorder."""

    def __init__(
        self,
        recorder: Optional[SessionRecorder] = None,
        target_host: str = "honeypot-ssh-01",
    ) -> None:
        self.recorder = recorder or SessionRecorder()
        self.target_host = target_host
        self._shells: dict[str, VirtualShell] = {}

    def handle_connection(
        self,
        source_ip: str,
        source_port: int = 0,
        protocol: str = "ssh",
        client_version: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> HoneypotSession:
        """Register a new connection from an attacker."""
        session = self.recorder.start_session(
            source_ip=source_ip,
            source_port=source_port,
            protocol=protocol,  # type: ignore[arg-type]
            target_host=self.target_host,
            client_version=client_version,
            session_id=session_id,
        )
        self._shells[session.session_id] = VirtualShell(hostname=self.target_host)
        return session

    def handle_auth(
        self,
        session_id: str,
        username: str,
        password: str,
        allow_login: bool = True,
    ) -> bool:
        """Process an authentication attempt."""
        session = self.recorder.get_session(session_id)
        if not session:
            return False

        # In a honeypot, we typically accept after N tries or accept common creds
        success = allow_login
        self.recorder.record_credential(
            session_id=session_id,
            username=username,
            password=password,
            success=success,
        )
        if success and session_id in self._shells:
            self._shells[session_id].current_user = username
            self._shells[session_id].cwd = "/root" if username == "root" else f"/home/{username}"

        return success

    def handle_command(self, session_id: str, command: str) -> tuple[str, int]:
        """Execute a command through the virtual shell and record the interaction."""
        shell = self._shells.get(session_id)
        if not shell:
            shell = VirtualShell(hostname=self.target_host)
            self._shells[session_id] = shell

        output, ret_code, ttp_cats, mitre_techs = shell.execute(command)

        # Check for simulated downloads
        if "download" in ttp_cats:
            parts = command.split()
            url = parts[-1] if parts else "payload.bin"
            dummy_hash = hashlib.sha256(command.encode()).hexdigest()
            self.recorder.record_artifact(
                session_id=session_id,
                filename_or_url=url,
                file_hash=dummy_hash,
                size_bytes=45056,
                transfer_type="download",
            )

        self.recorder.record_command(
            session_id=session_id,
            command=command,
            working_dir=shell.cwd,
            output_preview=output[:200],
            return_code=ret_code,
            tags=ttp_cats,
        )

        # Track MITRE techniques onto the session
        session = self.recorder.get_session(session_id)
        if session:
            for t in mitre_techs:
                if t not in session.mitre_techniques:
                    session.mitre_techniques.append(t)

        return output, ret_code

    def handle_disconnect(self, session_id: str) -> Optional[HoneypotSession]:
        """Finalize and close an attacker session."""
        self._shells.pop(session_id, None)
        return self.recorder.close_session(session_id)
