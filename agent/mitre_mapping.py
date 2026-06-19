"""A small MITRE ATT&CK (Enterprise) knowledge base used to annotate findings.

The triage agent collects "indicator tags" as it gathers evidence (e.g.
``encoded_powershell``, ``c2_beaconing``). This module maps those tags to
concrete ATT&CK techniques so the final report can cite technique IDs,
names, tactics, and a link to the official MITRE page.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        base_id = self.technique_id.split(".")[0]
        if "." in self.technique_id:
            sub_id = self.technique_id.split(".")[1]
            return f"https://attack.mitre.org/techniques/{base_id}/{sub_id}/"
        return f"https://attack.mitre.org/techniques/{base_id}/"

    def to_dict(self) -> dict:
        return {
            "id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "url": self.url,
        }


# Reference table of ATT&CK techniques relevant to the bundled scenarios.
TECHNIQUES: dict[str, Technique] = {
    "T1566.001": Technique("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    "T1204.002": Technique("T1204.002", "User Execution: Malicious File", "Execution"),
    "T1059.001": Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1027": Technique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1071.001": Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1110.001": Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "T1078.002": Technique("T1078.002", "Valid Accounts: Domain Accounts", "Persistence"),
    "T1087.002": Technique("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    "T1560.001": Technique("T1560.001", "Archive Collected Data: Archive via Utility", "Collection"),
    "T1074.001": Technique("T1074.001", "Data Staged: Local Data Staging", "Collection"),
    "T1567.002": Technique("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    "T1053.005": Technique("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1036.005": Technique("T1036.005", "Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
}

# Map indicator tags (emitted by scenario evidence steps) -> technique IDs.
INDICATOR_TECHNIQUE_MAP: dict[str, list[str]] = {
    "phishing_attachment": ["T1566.001", "T1204.002"],
    "office_spawned_shell": ["T1059.001"],
    "encoded_powershell": ["T1027"],
    "download_cradle": ["T1105"],
    "c2_beaconing": ["T1071.001"],
    "newly_registered_domain": ["T1036.005"],
    "brute_force_success": ["T1110.001"],
    "service_account_abuse": ["T1078.002"],
    "ad_recon": ["T1087.002"],
    "after_hours_archive_creation": ["T1560.001"],
    "sensitive_data_staging": ["T1074.001"],
    "large_outbound_transfer": ["T1567.002"],
    "typosquat_domain": ["T1036.005"],
    "scheduled_task_persistence": ["T1053.005"],
}


def map_indicators_to_techniques(indicator_tags: list[str]) -> list[dict]:
    """Return deduplicated ATT&CK technique dicts for the given indicator tags.

    Unknown tags (those without a mapping, e.g. purely contextual evidence
    like ``atypical_source_asset``) are silently ignored - they still appear
    in the evidence log but do not claim a specific technique.
    """

    seen: dict[str, Technique] = {}
    for tag in indicator_tags:
        for technique_id in INDICATOR_TECHNIQUE_MAP.get(tag, []):
            technique = TECHNIQUES.get(technique_id)
            if technique:
                seen[technique_id] = technique

    return [seen[tid].to_dict() for tid in sorted(seen)]
