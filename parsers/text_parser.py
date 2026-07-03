"""Generic log text parser.

Parses syslog, /var/log/auth.log, and other plain-text log formats
into GhostTrace ``auth_logs`` and ``process_tree`` artifacts using
regex pattern matching.  Malformed lines are silently skipped.
"""

import re
from typing import Any

from parsers.base import BaseParser


# Compiled regex patterns for common log line formats
# Syslog: "Jan 15 02:10:00 hostname process[pid]: message"
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$",
)

# SSH accepted password: "Accepted password for USER from IP port PORT"
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)

# SSH failed attempt: "Failed password for (invalid user )?USER from IP"
_SSH_FAILED_RE = re.compile(
    r"Failed\s+password\s+(?:for\s+(?:invalid\s+user\s+)?)(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"
)

# sudo: "USER : TTY=... ; COMMAND=..."
_SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<run_as>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

# UFW/kernel firewall block: "SRC= IP DST= IP PROTO= TCP DPT= PORT"
_FIREWALL_RE = re.compile(
    r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+PROTO=(?P<proto>\S+)"
    r"(?:\s+DPT=(?P<dport>\d+))?"
)

# NTLM authentication: "Accepted NTLM authentication for USER from IP"
_NTLM_AUTH_RE = re.compile(
    r"Accepted\s+NTLM\s+authentication\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"
)

# Generic user action: "user=USER" or "USER" followed by action keywords
_USER_ACTION_RE = re.compile(
    r"(?:user[=:]?\s*)(?P<user>\S+)"
)

# Connection authorized: "connection authorized: user=USER"
_CONNECTION_AUTH_RE = re.compile(
    r"connection\s+authorized.*?user=(?P<user>\S+)"
)

# WinRM / WSMan session
_WINRM_RE = re.compile(
    r"(?:session|connection).*?(?:from\s+(?P<src_ip>\S+))?.*?user\s+(?P<user>\S+)"
)

# Process with suspicious activity
_PROCESS_ACTIVITY_RE = re.compile(
    r"(?:process|exe)\s+(?P<process>\S+\.\S+)"
)

# Replication request
_REPLICATION_RE = re.compile(
    r"[Rr]eplication\s+request\s+from\s+(?P<src_ip>\S+)"
)

# Month name → month number
_MONTH_MAP: dict[str, str] = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


class TextParser(BaseParser):
    """Parse generic syslog/auth log text files into GhostTrace evidence artifacts."""

    format_name = "text"

    def can_parse(self, content: bytes, filename: str) -> bool:
        """Detect plain-text log files by extension or content sniffing."""
        lower = filename.lower()
        if lower.endswith(".txt") or lower.endswith(".log"):
            # Check it's not a Zeek log
            if "zeek" in lower or "conn" in lower:
                return False
            return True

        # Content sniffing: look for syslog-style timestamp patterns
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return False

        first_lines = text.split("\n")[:5]
        has_syslog = any(_SYSLOG_RE.match(line.strip()) for line in first_lines if line.strip())
        return has_syslog

    def parse(self, content: bytes, filename: str) -> dict:
        """Parse text log lines into GhostTrace evidence format."""
        evidence = self._make_empty_evidence(filename)

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return evidence

        auth_logs: list[dict[str, Any]] = []
        process_tree: list[dict[str, Any]] = []

        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            # Try to parse as syslog first
            syslog_match = _SYSLOG_RE.match(stripped)
            if syslog_match:
                parsed = self._parse_syslog_line(syslog_match, stripped)
                if parsed:
                    if parsed["category"] == "auth":
                        auth_logs.append(parsed["artifact"])
                    elif parsed["category"] == "process":
                        process_tree.append(parsed["artifact"])
                    else:
                        # Default to auth_logs for unmatched syslog lines
                        auth_logs.append(parsed["artifact"])
                continue

            # Try standalone patterns on non-syslog lines
            self._parse_standalone_line(stripped, auth_logs, process_tree)

        evidence["artifacts"]["auth_logs"] = auth_logs
        evidence["artifacts"]["process_tree"] = process_tree
        total = len(auth_logs) + len(process_tree)
        evidence["metadata"] = self._make_metadata(filename, self.format_name, total)
        return evidence

    def _parse_syslog_line(self, match: re.Match, raw_line: str) -> dict[str, Any] | None:
        """Parse a matched syslog line into an artifact."""
        try:
            month = _MONTH_MAP.get(match.group("month"), "01")
            day = match.group("day").zfill(2)
            time_str = match.group("time")
            host = match.group("host")
            process = match.group("process")
            message = match.group("message")

            # Build ISO timestamp (assume current year)
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            timestamp = f"{now.year}-{month}-{day}T{time_str}Z"

            # Classify by message content
            # SSH accepted
            ssh_match = _SSH_ACCEPTED_RE.search(message)
            if ssh_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "ssh_accepted",
                        "user": ssh_match.group("user"),
                        "src_ip": ssh_match.group("src_ip"),
                        "logon_type": "interactive",
                        "status": "success",
                    },
                }

            # SSH failed
            ssh_fail = _SSH_FAILED_RE.search(message)
            if ssh_fail:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "ssh_failed",
                        "user": ssh_fail.group("user"),
                        "src_ip": ssh_fail.group("src_ip"),
                        "logon_type": "interactive",
                        "status": "failure",
                    },
                }

            # sudo
            sudo_match = _SUDO_RE.search(message)
            if sudo_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "sudo",
                        "user": sudo_match.group("user"),
                        "src_ip": "",
                        "logon_type": "interactive",
                        "status": "success",
                    },
                }

            # Firewall block
            fw_match = _FIREWALL_RE.search(message)
            if fw_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "firewall_block",
                        "user": "",
                        "src_ip": fw_match.group("src_ip"),
                        "logon_type": "network",
                        "status": "blocked",
                    },
                }

            # NTLM auth
            ntlm_match = _NTLM_AUTH_RE.search(message)
            if ntlm_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "ntlm_auth",
                        "user": ntlm_match.group("user"),
                        "src_ip": ntlm_match.group("src_ip"),
                        "logon_type": "network",
                        "status": "success",
                    },
                }

            # Connection authorized (Postgres, etc.)
            conn_match = _CONNECTION_AUTH_RE.search(message)
            if conn_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "connection_authorized",
                        "user": conn_match.group("user"),
                        "src_ip": "",
                        "logon_type": "network",
                        "status": "success",
                    },
                }

            # WinRM session
            winrm_match = _WINRM_RE.search(message)
            if winrm_match and "user" in message.lower():
                user_val = winrm_match.group("user") if winrm_match.group("user") else ""
                src_val = winrm_match.group("src_ip") if winrm_match.group("src_ip") else ""
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "winrm_session",
                        "user": user_val,
                        "src_ip": src_val,
                        "logon_type": "remote",
                        "status": "success",
                    },
                }

            # Replication request
            repl_match = _REPLICATION_RE.search(message)
            if repl_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": "ad_replication",
                        "user": "",
                        "src_ip": repl_match.group("src_ip"),
                        "logon_type": "network",
                        "status": "success",
                    },
                }

            # Suspicious process activity
            proc_match = _PROCESS_ACTIVITY_RE.search(message)
            if proc_match:
                return {
                    "category": "process",
                    "artifact": {
                        "timestamp": timestamp,
                        "pid": 0,
                        "parent_pid": 0,
                        "process_name": proc_match.group("process"),
                        "command_line": message,
                        "user": "",
                    },
                }

            # Generic auth line fallback
            user_match = _USER_ACTION_RE.search(message)
            if user_match:
                return {
                    "category": "auth",
                    "artifact": {
                        "timestamp": timestamp,
                        "event_id": f"syslog_{process}",
                        "user": user_match.group("user"),
                        "src_ip": "",
                        "logon_type": "",
                        "status": "",
                    },
                }

            # Unparseable but valid syslog line — skip
            return None

        except Exception:
            return None

    def _parse_standalone_line(
        self,
        line: str,
        auth_logs: list[dict[str, Any]],
        process_tree: list[dict[str, Any]],
    ) -> None:
        """Try to parse a non-syslog line using standalone patterns."""
        # Process with suspicious activity (e.g., falco output)
        proc_match = _PROCESS_ACTIVITY_RE.search(line)
        if proc_match:
            # Try to find an IP
            ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
            src_ip = ip_match.group(1) if ip_match else ""

            auth_logs.append({
                "timestamp": "",
                "event_id": "process_activity",
                "user": "",
                "src_ip": src_ip,
                "logon_type": "",
                "status": "suspicious",
            })
