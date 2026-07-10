"""
One-time generator for mitre_full.json.

Builds full MITRE ATT&CK coverage for every technique ID referenced by
the ingested HEARTH hypothesis set (data/knowledge_base/hearth/hearth_full.json),
merging in the hand-curated, richly-described entries from
services/knowledge/seeds/mitre_seed.json.

Grounding rules (no invented facts):
  - tactic: taken directly from the hearth hypothesis data (all_tactics),
    which is authoritative for this dataset — never guessed.
  - name/description for a technique's BASE id (e.g. T1003 for T1003.001):
    taken from BASE_TECHNIQUES, a curated table of canonical MITRE ATT&CK
    Enterprise technique names (stable, versioned public knowledge).
  - sub-techniques inherit the base name with a qualifier, and get a
    description grounded in the actual hunting-hypothesis text that
    references them (not invented) when a curated sub-technique name
    isn't available.
Run manually: python3 _generate_mitre_full.py
"""
import json
import os
import re
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
HEARTH_PATH = os.path.join(REPO_ROOT, "data", "knowledge_base", "hearth", "hearth_full.json")
SEED_PATH = os.path.join(HERE, "..", "seeds", "mitre_seed.json")
OUT_PATH = os.path.join(HERE, "mitre_full.json")

# Canonical MITRE ATT&CK Enterprise base-technique names + default tactic +
# typical data sources. This is the well-established, versioned public
# framework — names/IDs are stable reference data, not runtime facts.
BASE_TECHNIQUES = {
    "T1003": ("OS Credential Dumping", ["LSASS Memory", "Security Account Manager", "Authentication Logs"]),
    "T1005": ("Data from Local System", ["File Monitoring", "Process Creation"]),
    "T1018": ("Remote System Discovery", ["Network Traffic", "Process Creation"]),
    "T1020": ("Automated Exfiltration", ["Network Traffic", "File Monitoring"]),
    "T1021": ("Remote Services", ["Authentication Logs", "Network Traffic", "Process Creation"]),
    "T1027": ("Obfuscated Files or Information", ["File Monitoring", "Process Creation"]),
    "T1030": ("Data Transfer Size Limits", ["Network Traffic"]),
    "T1036": ("Masquerading", ["File Monitoring", "Process Creation"]),
    "T1037": ("Boot or Logon Initialization Scripts", ["Process Creation", "Windows Registry"]),
    "T1039": ("Data from Network Shared Drive", ["File Monitoring", "Network Traffic"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Network Traffic"]),
    "T1046": ("Network Service Discovery", ["Network Traffic", "Process Creation"]),
    "T1047": ("Windows Management Instrumentation", ["Process Creation", "WMI Logs"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Network Traffic"]),
    "T1049": ("System Network Connections Discovery", ["Process Creation", "Network Traffic"]),
    "T1052": ("Exfiltration Over Physical Medium", ["File Monitoring", "Removable Media"]),
    "T1053": ("Scheduled Task/Job", ["Process Creation", "Scheduled Job Logs", "Windows Registry"]),
    "T1055": ("Process Injection", ["Process Access", "Process Creation"]),
    "T1056": ("Input Capture", ["Process Creation", "Driver/Module Load"]),
    "T1059": ("Command and Scripting Interpreter", ["Command Execution", "Process Creation"]),
    "T1068": ("Exploitation for Privilege Escalation", ["Process Creation", "Application Logs"]),
    "T1069": ("Permission Groups Discovery", ["Process Creation", "Authentication Logs"]),
    "T1070": ("Indicator Removal", ["Windows Event Logs", "File Monitoring"]),
    "T1071": ("Application Layer Protocol", ["Network Traffic", "DNS Logs"]),
    "T1074": ("Data Staged", ["File Monitoring", "Process Creation"]),
    "T1078": ("Valid Accounts", ["Authentication Logs", "Process Creation"]),
    "T1082": ("System Information Discovery", ["Process Creation"]),
    "T1083": ("File and Directory Discovery", ["Process Creation", "File Monitoring"]),
    "T1087": ("Account Discovery", ["Process Creation", "Authentication Logs"]),
    "T1090": ("Proxy", ["Network Traffic"]),
    "T1091": ("Replication Through Removable Media", ["File Monitoring", "Removable Media"]),
    "T1092": ("Communication Through Removable Media", ["Removable Media"]),
    "T1095": ("Non-Application Layer Protocol", ["Network Traffic"]),
    "T1098": ("Account Manipulation", ["Authentication Logs", "Windows Registry"]),
    "T1102": ("Web Service", ["Network Traffic", "DNS Logs"]),
    "T1105": ("Ingress Tool Transfer", ["Network Traffic", "File Monitoring"]),
    "T1106": ("Native API", ["Process Creation", "API Monitoring"]),
    "T1110": ("Brute Force", ["Authentication Logs"]),
    "T1112": ("Modify Registry", ["Windows Registry"]),
    "T1114": ("Email Collection", ["Application Logs", "Email Gateway Logs"]),
    "T1115": ("Clipboard Data", ["Process Access"]),
    "T1119": ("Automated Collection", ["File Monitoring", "Process Creation"]),
    "T1127": ("Trusted Developer Utilities Proxy Execution", ["Process Creation"]),
    "T1133": ("External Remote Services", ["Authentication Logs", "Network Traffic"]),
    "T1134": ("Access Token Manipulation", ["Process Access", "Process Creation"]),
    "T1135": ("Network Share Discovery", ["Process Creation", "Network Traffic"]),
    "T1136": ("Create Account", ["Authentication Logs", "Windows Registry"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["Process Creation", "File Monitoring"]),
    "T1176": ("Browser Extensions", ["File Monitoring", "Process Creation"]),
    "T1185": ("Browser Session Hijacking", ["Process Access", "Network Traffic"]),
    "T1187": ("Forced Authentication", ["Network Traffic", "Authentication Logs"]),
    "T1189": ("Drive-by Compromise", ["Network Traffic", "Process Creation"]),
    "T1190": ("Exploit Public-Facing Application", ["Application Logs", "Network Traffic"]),
    "T1195": ("Supply Chain Compromise", ["File Monitoring", "Application Logs"]),
    "T1197": ("BITS Jobs", ["Process Creation", "Network Traffic"]),
    "T1199": ("Trusted Relationship", ["Authentication Logs"]),
    "T1200": ("Hardware Additions", ["Driver/Module Load"]),
    "T1203": ("Exploitation for Client Execution", ["Process Creation", "Application Logs"]),
    "T1204": ("User Execution", ["Process Creation", "File Monitoring"]),
    "T1205": ("Traffic Signaling", ["Network Traffic"]),
    "T1211": ("Exploitation for Defense Evasion", ["Process Creation"]),
    "T1213": ("Data from Information Repositories", ["Application Logs"]),
    "T1218": ("System Binary Proxy Execution", ["Process Creation"]),
    "T1219": ("Remote Access Software", ["Network Traffic", "Process Creation"]),
    "T1222": ("File and Directory Permissions Modification", ["File Monitoring", "Process Creation"]),
    "T1482": ("Domain Trust Discovery", ["Process Creation", "Active Directory Logs"]),
    "T1484": ("Domain or Tenant Policy Modification", ["Active Directory Logs", "Windows Registry"]),
    "T1485": ("Data Destruction", ["File Monitoring"]),
    "T1486": ("Data Encrypted for Impact", ["File Monitoring", "Process Creation"]),
    "T1489": ("Service Stop", ["Process Creation", "Windows Event Logs"]),
    "T1490": ("Inhibit System Recovery", ["Process Creation", "Windows Event Logs"]),
    "T1491": ("Defacement", ["File Monitoring"]),
    "T1497": ("Virtualization/Sandbox Evasion", ["Process Creation"]),
    "T1505": ("Server Software Component", ["File Monitoring", "Application Logs"]),
    "T1518": ("Software Discovery", ["Process Creation"]),
    "T1526": ("Cloud Service Discovery", ["Cloud API Logs"]),
    "T1528": ("Steal Application Access Token", ["Authentication Logs"]),
    "T1531": ("Account Access Removal", ["Authentication Logs"]),
    "T1534": ("Internal Spearphishing", ["Email Gateway Logs"]),
    "T1537": ("Transfer Data to Cloud Account", ["Cloud API Logs", "Network Traffic"]),
    "T1539": ("Steal Web Session Cookie", ["File Monitoring", "Process Access"]),
    "T1543": ("Create or Modify System Process", ["Process Creation", "Windows Registry"]),
    "T1546": ("Event Triggered Execution", ["Process Creation", "Windows Registry"]),
    "T1547": ("Boot or Logon Autostart Execution", ["Windows Registry", "Process Creation"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["Process Creation", "Windows Registry"]),
    "T1550": ("Use Alternate Authentication Material", ["Authentication Logs"]),
    "T1552": ("Unsecured Credentials", ["File Monitoring", "Process Creation"]),
    "T1553": ("Subvert Trust Controls", ["File Monitoring", "Windows Registry"]),
    "T1554": ("Compromise Client Software Binary", ["File Monitoring"]),
    "T1555": ("Credentials from Password Stores", ["File Monitoring", "Process Access"]),
    "T1556": ("Modify Authentication Process", ["Authentication Logs", "Windows Registry"]),
    "T1557": ("Adversary-in-the-Middle", ["Network Traffic"]),
    "T1559": ("Inter-Process Communication", ["Process Access"]),
    "T1560": ("Archive Collected Data", ["File Monitoring", "Process Creation"]),
    "T1562": ("Impair Defenses", ["Windows Event Logs", "Process Creation"]),
    "T1564": ("Hide Artifacts", ["File Monitoring", "Windows Registry"]),
    "T1566": ("Phishing", ["Email Gateway Logs", "File Monitoring"]),
    "T1567": ("Exfiltration Over Web Service", ["Network Traffic"]),
    "T1568": ("Dynamic Resolution", ["DNS Logs"]),
    "T1569": ("System Services", ["Process Creation", "Windows Event Logs"]),
    "T1570": ("Lateral Tool Transfer", ["Network Traffic", "File Monitoring"]),
    "T1572": ("Protocol Tunneling", ["Network Traffic"]),
    "T1573": ("Encrypted Channel", ["Network Traffic"]),
    "T1574": ("Hijack Execution Flow", ["Process Creation", "Windows Registry"]),
    "T1580": ("Cloud Infrastructure Discovery", ["Cloud API Logs"]),
    "T1583": ("Acquire Infrastructure", ["Network Traffic"]),
    "T1595": ("Active Scanning", ["Network Traffic"]),
    "T1599": ("Network Boundary Bridging", ["Network Traffic"]),
    "T1611": ("Escape to Host", ["Process Creation", "Container Logs"]),
    "T1619": ("Cloud Storage Object Discovery", ["Cloud API Logs"]),
    "T1620": ("Reflective Code Loading", ["Process Access", "Driver/Module Load"]),
    "T1621": ("Multi-Factor Authentication Request Generation", ["Authentication Logs"]),
    "T1649": ("Steal or Forge Authentication Certificates", ["File Monitoring", "Authentication Logs"]),
    "T1651": ("Cloud Administration Command", ["Cloud API Logs"]),
    "T0847": ("Replication Through Removable Media (ICS)", ["File Monitoring", "Removable Media"]),
}


def base_id(technique_id: str) -> str:
    return technique_id.split(".")[0]


def main():
    with open(HEARTH_PATH) as f:
        hearth = json.load(f)
    with open(SEED_PATH) as f:
        seed = json.load(f)

    seed_by_id = {t["id"]: t for t in seed}

    # technique_id -> Counter of tactics seen across hypotheses (authoritative, grounded)
    tactic_votes = defaultdict(Counter)
    # technique_id -> list of hypothesis titles/text mentioning it (grounded description source)
    grounding_text = defaultdict(list)

    for h in hearth:
        tids = set(h.get("all_techniques", []))
        if h.get("technique"):
            tids.add(h["technique"])
        for tac in h.get("all_tactics", []) or ([h["tactic"]] if h.get("tactic") else []):
            for tid in tids:
                tactic_votes[tid][tac] += 1
        for tid in tids:
            if h.get("title"):
                grounding_text[tid].append(h["title"])

    all_ids = set(tactic_votes) | set(seed_by_id)

    table = {}
    for tid in sorted(all_ids):
        bid = base_id(tid)
        tactic = tactic_votes[tid].most_common(1)[0][0] if tactic_votes[tid] else (
            seed_by_id.get(tid, {}).get("tactic", "Unknown")
        )

        if tid in seed_by_id:
            s = seed_by_id[tid]
            table[tid] = {
                "id": tid,
                "name": s["name"],
                "tactic": tactic or s.get("tactic", "Unknown"),
                "description": s["description"],
                "data_sources": s.get("data_sources", []),
                "source": "curated",
            }
            continue

        if bid in BASE_TECHNIQUES:
            base_name, data_sources = BASE_TECHNIQUES[bid]
            if tid == bid:
                name = base_name
            else:
                # Sub-technique: keep it honest — qualify with the base
                # name rather than inventing a specific sub-technique title.
                name = f"{base_name} (sub-technique {tid})"
            examples = grounding_text.get(tid, [])
            description = (
                f"{base_name}. Referenced by {len(examples)} hunting hypothesis(es) in this "
                f"platform's HEARTH knowledge base"
                + (f", e.g.: \"{examples[0][:180]}\"" if examples else "")
                + "."
            )
            table[tid] = {
                "id": tid,
                "name": name,
                "tactic": tactic or "Unknown",
                "description": description,
                "data_sources": data_sources,
                "source": "base-technique-table+hearth-grounded",
            }
        else:
            examples = grounding_text.get(tid, [])
            table[tid] = {
                "id": tid,
                "name": f"Technique {tid} (name not in curated table)",
                "tactic": tactic or "Unknown",
                "description": (
                    f"Referenced by {len(examples)} hunting hypothesis(es): "
                    f"\"{examples[0][:200]}\"" if examples else
                    "No curated name available for this technique ID yet."
                ),
                "data_sources": [],
                "source": "hearth-grounded-only",
            }

    with open(OUT_PATH, "w") as f:
        json.dump(table, f, indent=2, sort_keys=True)

    curated = sum(1 for t in table.values() if t["source"] == "curated")
    base_tbl = sum(1 for t in table.values() if t["source"] == "base-technique-table+hearth-grounded")
    ungrounded = sum(1 for t in table.values() if t["source"] == "hearth-grounded-only")
    print(f"Wrote {len(table)} techniques to {OUT_PATH}")
    print(f"  curated (seed file):              {curated}")
    print(f"  base-table name + grounded tactic: {base_tbl}")
    print(f"  hearth-grounded only (no name):    {ungrounded}")


if __name__ == "__main__":
    main()
