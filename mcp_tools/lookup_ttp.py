"""MITRE ATT&CK Technique Lookup MCP Tool.

This module provides the `lookup_ttp` MCP tool that allows agents to look up
MITRE ATT&CK technique details by technique ID. It maintains a curated dictionary
of techniques covering all 12 ATT&CK tactics, enabling agents to enrich their
analysis with standardized threat intelligence context.

Each technique entry includes the technique name, associated tactic, known
sub-techniques, a brief description, and a detection hint to guide defenders.
"""

import json

# Module-level dictionary of MITRE ATT&CK techniques covering all 12 tactics.
# Each entry maps a technique ID to its metadata.
MITRE_TECHNIQUES: dict[str, dict] = {
    # --- Initial Access ---
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "subtechniques": [],
        "description": (
            "Adversaries may attempt to exploit a weakness in an Internet-facing "
            "host or system to initially access a network. This includes web servers, "
            "databases, and other externally accessible services."
        ),
        "detection_hint": (
            "Monitor application logs for unusual error patterns, unexpected input "
            "payloads, and anomalous process spawning from web service accounts."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "subtechniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts to "
            "gain initial access, persistence, privilege escalation, or defense evasion. "
            "Compromised credentials may include default, local, domain, or cloud accounts."
        ),
        "detection_hint": (
            "Monitor for logon attempts from unusual source IPs, impossible travel, "
            "or access outside normal working hours for the account."
        ),
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "subtechniques": ["T1566.001", "T1566.002", "T1566.003"],
        "description": (
            "Adversaries may send phishing messages to gain access to victim systems. "
            "This includes spearphishing attachments, links, and via service."
        ),
        "detection_hint": (
            "Monitor email gateways for suspicious attachments, URL reputation checks, "
            "and user-reported phishing. Correlate with endpoint process creation events."
        ),
    },
    # --- Execution ---
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "subtechniques": [
            "T1059.001", "T1059.002", "T1059.003", "T1059.004",
            "T1059.005", "T1059.006", "T1059.007", "T1059.008",
        ],
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, "
            "scripts, or binaries. These interfaces include PowerShell, Windows Command "
            "Shell, Unix shells, Python, JavaScript, and others."
        ),
        "detection_hint": (
            "Monitor process creation for scripting engines (powershell.exe, cmd.exe, "
            "wscript.exe, python.exe). Log command-line arguments and script block content."
        ),
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "subtechniques": [],
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for execution. "
            "PowerShell is a powerful interactive command-line interface and scripting "
            "environment included in the Windows operating system."
        ),
        "detection_hint": (
            "Enable PowerShell script block logging and module logging. Monitor for "
            "encoded commands (-enc), download cradles (IEX, Invoke-WebRequest), "
            "and execution policy bypasses."
        ),
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "subtechniques": [],
        "description": (
            "Adversaries may abuse the Windows command shell (cmd.exe) for execution. "
            "The command shell is used to control almost any aspect of a system, with "
            "various permission levels required for different subsets of commands."
        ),
        "detection_hint": (
            "Monitor cmd.exe process creation events, especially when spawned by "
            "unusual parent processes (e.g., Office applications, services). "
            "Log command-line arguments for suspicious patterns."
        ),
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "subtechniques": ["T1204.001", "T1204.002", "T1204.003"],
        "description": (
            "An adversary may rely upon specific actions by a user in order to gain "
            "execution. Users may be subjected to social engineering to get them to "
            "execute malicious code."
        ),
        "detection_hint": (
            "Monitor for Office applications spawning child processes, users opening "
            "files from email attachments, and execution of recently downloaded files."
        ),
    },
    # --- Persistence ---
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "subtechniques": [
            "T1547.001", "T1547.002", "T1547.003", "T1547.004",
            "T1547.005", "T1547.009",
        ],
        "description": (
            "Adversaries may configure system settings to automatically execute a "
            "program during system boot or logon to maintain persistence. This includes "
            "registry Run keys, startup folders, and authentication packages."
        ),
        "detection_hint": (
            "Monitor registry Run/RunOnce keys, Startup folder contents, and scheduled "
            "tasks. Alert on new entries or modifications to autostart locations."
        ),
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "subtechniques": ["T1543.001", "T1543.002", "T1543.003", "T1543.004"],
        "description": (
            "Adversaries may create or modify system-level processes to repeatedly "
            "execute malicious payloads as part of persistence. This includes Windows "
            "services, systemd services, and launch daemons."
        ),
        "detection_hint": (
            "Monitor for new service installations (sc.exe, New-Service), modifications "
            "to existing service binaries, and unusual service account configurations."
        ),
    },
    # --- Privilege Escalation ---
    "T1055": {
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "subtechniques": [
            "T1055.001", "T1055.002", "T1055.003", "T1055.004",
            "T1055.005", "T1055.008", "T1055.012",
        ],
        "description": (
            "Adversaries may inject code into processes in order to evade process-based "
            "defenses as well as possibly elevate privileges. Process injection involves "
            "running arbitrary code in the address space of a separate live process."
        ),
        "detection_hint": (
            "Monitor for API calls associated with injection (WriteProcessMemory, "
            "CreateRemoteThread, NtMapViewOfSection). Detect cross-process memory access."
        ),
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "subtechniques": ["T1548.001", "T1548.002", "T1548.003", "T1548.004"],
        "description": (
            "Adversaries may circumvent mechanisms designed to control elevated "
            "privileges to gain higher-level permissions. This includes UAC bypass, "
            "sudo exploitation, and setuid/setgid abuse."
        ),
        "detection_hint": (
            "Monitor for UAC bypass techniques (fodhelper.exe, eventvwr.exe), "
            "unexpected sudo usage, and processes running with elevated privileges "
            "from non-standard paths."
        ),
    },
    # --- Defense Evasion ---
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "subtechniques": [
            "T1070.001", "T1070.002", "T1070.003", "T1070.004",
            "T1070.005", "T1070.006",
        ],
        "description": (
            "Adversaries may delete or modify artifacts generated within systems to "
            "remove evidence of their presence or hinder defenses. This includes "
            "clearing event logs, deleting files, and timestomping."
        ),
        "detection_hint": (
            "Monitor for event log clearing (wevtutil cl, Clear-EventLog), file "
            "deletion in sensitive directories, and timestamp modifications on "
            "recently created files."
        ),
    },
    "T1112": {
        "name": "Modify Registry",
        "tactic": "Defense Evasion",
        "subtechniques": [],
        "description": (
            "Adversaries may interact with the Windows Registry to hide configuration "
            "information within Registry keys, remove information as part of cleaning "
            "up, or as part of other techniques to aid in persistence and execution."
        ),
        "detection_hint": (
            "Monitor registry modifications to security-sensitive keys (Run, Services, "
            "Security). Alert on reg.exe usage and direct registry API calls from "
            "unexpected processes."
        ),
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "subtechniques": [
            "T1562.001", "T1562.002", "T1562.003", "T1562.004",
            "T1562.006", "T1562.007", "T1562.008",
        ],
        "description": (
            "Adversaries may maliciously modify components of a victim environment "
            "to hinder or disable defensive mechanisms. This includes disabling "
            "security tools, modifying firewall rules, and impairing logging."
        ),
        "detection_hint": (
            "Monitor for security tool process termination, DisableAntiSpyware "
            "registry keys, firewall rule modifications, and audit policy changes."
        ),
    },
    # --- Credential Access ---
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "subtechniques": [
            "T1003.001", "T1003.002", "T1003.003", "T1003.004",
            "T1003.005", "T1003.006",
        ],
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login and "
            "credential material from the operating system and software. This includes "
            "LSASS memory, SAM database, and cached domain credentials."
        ),
        "detection_hint": (
            "Monitor for access to LSASS process memory, SAM registry hive exports, "
            "and tools like Mimikatz, procdump, or comsvcs.dll MiniDump."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "subtechniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained. This "
            "includes password guessing, spraying, and credential stuffing."
        ),
        "detection_hint": (
            "Monitor for multiple failed authentication attempts from single sources, "
            "password spray patterns (one password across many accounts), and account "
            "lockout events."
        ),
    },
    # --- Discovery ---
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "subtechniques": [],
        "description": (
            "An adversary may attempt to get detailed information about the operating "
            "system and hardware, including version, patches, hotfixes, service packs, "
            "and architecture."
        ),
        "detection_hint": (
            "Monitor for execution of systeminfo, hostname, ver commands, and WMI "
            "queries for system information, especially in rapid succession."
        ),
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "subtechniques": [],
        "description": (
            "Adversaries may enumerate files and directories or search in specific "
            "locations of a host or network share for certain information within a "
            "file system."
        ),
        "detection_hint": (
            "Monitor for excessive directory listing commands (dir, ls, find), "
            "especially targeting sensitive paths like user profiles, network shares, "
            "and configuration directories."
        ),
    },
    # --- Lateral Movement ---
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "subtechniques": [
            "T1021.001", "T1021.002", "T1021.003", "T1021.004",
            "T1021.005", "T1021.006",
        ],
        "description": (
            "Adversaries may use valid accounts to log into a service that accepts "
            "remote connections, such as RDP, SSH, SMB, or WinRM, to move laterally "
            "within a network."
        ),
        "detection_hint": (
            "Monitor for unusual remote logon events (Type 3, 10), lateral RDP "
            "connections between workstations, and SMB/WinRM sessions from "
            "non-administrative hosts."
        ),
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "subtechniques": [],
        "description": (
            "Adversaries may transfer tools or other files between systems in a "
            "compromised environment. Files may be copied from one system to another "
            "to stage adversary tools or other files over the course of an operation."
        ),
        "detection_hint": (
            "Monitor for SMB file transfers between internal hosts, especially "
            "executable files. Detect PsExec-style service installations and "
            "admin share (C$, ADMIN$) access."
        ),
    },
    # --- Collection ---
    "T1074": {
        "name": "Data Staged",
        "tactic": "Collection",
        "subtechniques": ["T1074.001", "T1074.002"],
        "description": (
            "Adversaries may stage collected data in a central location or directory "
            "prior to exfiltration. Data may be kept in separate files or combined "
            "into one file through techniques such as archive collected data."
        ),
        "detection_hint": (
            "Monitor for creation of archive files (zip, rar, 7z) in temp directories, "
            "large file aggregations, and unusual write activity to staging locations."
        ),
    },
    # --- Command and Control ---
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechniques": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"],
        "description": (
            "Adversaries may communicate using OSI application layer protocols to "
            "avoid detection by blending in with existing traffic. Commands to the "
            "remote system and results may be embedded within the protocol traffic."
        ),
        "detection_hint": (
            "Monitor for unusual HTTP/HTTPS beaconing patterns, DNS tunneling "
            "(high query volume, long subdomain labels), and traffic to newly "
            "registered or low-reputation domains."
        ),
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechniques": [],
        "description": (
            "Adversaries may use an OSI non-application layer protocol for "
            "communication between host and C2 server or among infected hosts. "
            "This includes ICMP, UDP, and custom protocols."
        ),
        "detection_hint": (
            "Monitor for unusual ICMP traffic patterns, raw socket usage, and "
            "non-standard protocol traffic on unexpected ports. Detect large or "
            "frequent ICMP echo payloads."
        ),
    },
    # --- Exfiltration ---
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "subtechniques": [],
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing command "
            "and control channel. Stolen data is encoded into the normal communications "
            "channel using the same protocol as C2 communications."
        ),
        "detection_hint": (
            "Monitor for unusually large outbound data transfers over established C2 "
            "channels, increased upload volume to known-bad IPs, and data encoding "
            "patterns in HTTP POST bodies."
        ),
    },
    # --- Impact ---
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "subtechniques": [],
        "description": (
            "Adversaries may encrypt data on target systems or on large numbers of "
            "systems in a network to interrupt availability to system and network "
            "resources. This is commonly associated with ransomware operations."
        ),
        "detection_hint": (
            "Monitor for mass file rename operations (new extensions), high entropy "
            "file writes, ransom note creation, and volume shadow copy deletion "
            "(vssadmin, wmic shadowcopy)."
        ),
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "subtechniques": [],
        "description": (
            "Adversaries may delete or remove built-in data and turn off services "
            "designed to aid in the recovery of a corrupted system. This includes "
            "deleting shadow copies, disabling recovery mode, and removing backups."
        ),
        "detection_hint": (
            "Monitor for vssadmin delete shadows, bcdedit /set recoveryenabled no, "
            "wbadmin delete catalog, and deletion of Windows backup files."
        ),
    },
    "T1491": {
        "name": "Defacement",
        "tactic": "Impact",
        "subtechniques": ["T1491.001", "T1491.002"],
        "description": (
            "Adversaries may modify visual content available internally or externally "
            "to an enterprise network, thus affecting the integrity of the original "
            "content. This includes website defacement and internal message modification."
        ),
        "detection_hint": (
            "Monitor for unauthorized modifications to web server content, changes "
            "to desktop wallpapers across multiple systems, and mass file content "
            "replacement."
        ),
    },
}


def lookup_ttp(technique_id: str) -> str:
    """Look up MITRE ATT&CK technique details by ID.

    Searches the curated MITRE ATT&CK technique database for the given
    technique ID and returns its full metadata including name, tactic,
    sub-techniques, description, and detection guidance.

    Supports both top-level technique IDs (e.g., "T1059") and sub-technique
    IDs (e.g., "T1059.001"). The lookup is case-sensitive and expects the
    standard MITRE format: T followed by 4 digits, optionally followed by
    a dot and 3 digits for sub-techniques.

    Args:
        technique_id: The MITRE ATT&CK technique identifier to look up.
            Examples: "T1059", "T1059.001", "T1190", "T1486".

    Returns:
        A JSON string containing either:
        - The full technique details (name, tactic, subtechniques, description,
          detection_hint) on success.
        - {"error": "Technique not found", "technique_id": "..."} if the
          technique ID is not in the database.
    """
    technique = MITRE_TECHNIQUES.get(technique_id)

    if technique is None:
        return json.dumps({
            "error": "Technique not found",
            "technique_id": technique_id,
        })

    return json.dumps({
        "technique_id": technique_id,
        "name": technique["name"],
        "tactic": technique["tactic"],
        "subtechniques": technique["subtechniques"],
        "description": technique["description"],
        "detection_hint": technique["detection_hint"],
    })
