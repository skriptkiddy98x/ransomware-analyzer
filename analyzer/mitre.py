"""Minimal MITRE ATT&CK lookup for the techniques this tool references."""

TECHNIQUES = {
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1055": ("Process Injection", "Defense Evasion / Privilege Escalation"),
    "T1055.001": ("Process Injection: DLL Injection", "Defense Evasion"),
    "T1055.004": ("Process Injection: APC Injection", "Defense Evasion"),
    "T1055.012": ("Process Injection: Process Hollowing", "Defense Evasion"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1135": ("Network Share Discovery", "Discovery"),
    "T1222": ("File and Directory Permissions Modification", "Defense Evasion"),
    "T1485": ("Data Destruction", "Impact"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1622": ("Debugger Evasion", "Defense Evasion"),
}


def describe(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, ("Unknown technique", "Unknown"))
    base = tid.split(".")[0]
    url = f"https://attack.mitre.org/techniques/{base}/"
    if "." in tid:
        url = f"https://attack.mitre.org/techniques/{base}/{tid.split('.')[1]}/"
    return {"id": tid, "name": name, "tactic": tactic, "url": url}


def describe_all(ids) -> list[dict]:
    return [describe(t) for t in sorted(set(ids))]
