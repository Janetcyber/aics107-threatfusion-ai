"""
Synthetic CTI Report Generator
================================
Generates safe, fully synthetic cyber threat intelligence (CTI) reports
for the ThreatFusion AI pipeline. All indicators use IANA-reserved
documentation ranges (RFC 5737 IPs, .example/.test/.invalid domains) —
none of this data can resolve to or affect a real system.

Each report is tagged with ground-truth MITRE ATT&CK technique labels,
used later to train and evaluate the ATT&CK mapping classifier (Lab 4).
"""

import json
import random
import os
from datetime import datetime, timedelta

SEED = 42
random.seed(SEED)

# ----------------------------------------------------------------------
# Safe synthetic indicator pools (RFC 5737 / IANA reserved-for-documentation)
# ----------------------------------------------------------------------
SAFE_IP_RANGES = ["192.0.2", "198.51.100", "203.0.113"]  # TEST-NET-1/2/3
SAFE_DOMAIN_TLDS = ["example", "test", "invalid"]
SOURCE_FEEDS = [
    "Internal SIEM Alert", "Vendor Threat Report", "OSINT Community Feed",
    "Endpoint Detection Alert", "Partner ISAC Bulletin", "Honeypot Telemetry",
]
TLP_LEVELS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]

# ----------------------------------------------------------------------
# Scenario definitions: each scenario maps to a set of plausible
# MITRE ATT&CK techniques and a narrative template with IOC placeholders.
# ----------------------------------------------------------------------
SCENARIOS = [
    {
        "name": "phishing_intrusion",
        "techniques": ["T1566.001", "T1059.001", "T1105", "T1027"],
        "template": (
            "On {date}, an employee at {org} opened an attachment from a spearphishing "
            "email originating from a spoofed vendor domain {domain}. The attachment "
            "executed an obfuscated PowerShell script that downloaded a secondary "
            "payload from {ip} using an encoded command line. The payload was staged "
            "under a randomized filename to evade static detection."
        ),
    },
    {
        "name": "ransomware_deployment",
        "techniques": ["T1486", "T1053.005", "T1078", "T1027"],
        "template": (
            "A ransomware incident was identified at {org} on {date}. The threat actor "
            "leveraged valid domain administrator credentials to create a scheduled task "
            "that executed a file-encryption routine across mapped network shares, staged "
            "from a host that had recently connected to {ip}. Encrypted files were appended "
            "with a randomized extension, and a ransom note referenced a payment portal at "
            "{domain}."
        ),
    },
    {
        "name": "c2_botnet",
        "techniques": ["T1071.001", "T1105", "T1046", "T1041"],
        "template": (
            "Network telemetry from {org} on {date} showed periodic beaconing traffic "
            "from an internal host to {ip} over HTTPS, consistent with command-and-control "
            "activity. The implant performed internal network service discovery before "
            "exfiltrating a small archive over the same C2 channel to {domain}."
        ),
    },
    {
        "name": "credential_access",
        "techniques": ["T1110", "T1003", "T1078"],
        "template": (
            "{org}'s authentication logs on {date} showed a high-volume password-spraying "
            "campaign against externally-facing services from source address {ip}, "
            "followed by a successful login and subsequent use of a credential-dumping "
            "utility on the compromised host. Post-compromise traffic was later observed "
            "to a related staging domain, {domain}."
        ),
    },
    {
        "name": "privilege_escalation",
        "techniques": ["T1548", "T1078", "T1059.003"],
        "template": (
            "Endpoint detection at {org} flagged an attempt on {date} to abuse a "
            "misconfigured elevation-control mechanism via a Windows command shell, "
            "shortly after a login using a valid but rarely-used service account. "
            "The activity originated from a host recently observed communicating "
            "with {ip}, which had earlier resolved a lookup for {domain}."
        ),
    },
    {
        "name": "reconnaissance_scan",
        "techniques": ["T1046"],
        "template": (
            "Passive monitoring at {org} on {date} detected a network service "
            "discovery scan originating from {ip}, sweeping common service ports "
            "across the external-facing subnet. No successful exploitation or "
            "follow-on activity was observed; the scan appears consistent with "
            "routine reconnaissance rather than an active intrusion. The source "
            "was later seen briefly resolving {domain}."
        ),
    },
]

ORG_NAMES = [
    "Northbridge Financial", "Aegis Health Systems", "Riverside University",
    "Meridian Public Schools", "Coastal Utilities Authority", "Vantage Logistics",
    "Sunridge Municipal Services", "Falcon Manufacturing", "Clearwater Bank",
    "Harborview Medical Group",
]


def random_safe_ip():
    base = random.choice(SAFE_IP_RANGES)
    return f"{base}.{random.randint(2, 254)}"


def random_safe_domain():
    words = ["update", "secure-login", "portal", "cdn-assets", "mail-relay", "vpn-gateway"]
    tld = random.choice(SAFE_DOMAIN_TLDS)
    return f"{random.choice(words)}-{random.randint(100,999)}.{tld}"


def random_hash():
    return "".join(random.choices("abcdef0123456789", k=64))


def random_date(days_back=180):
    d = datetime.now() - timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")


def defang(indicator):
    """Defang an indicator for safe display in reports (per lab safety requirement)."""
    return indicator.replace(".", "[.]")


def generate_report(report_id):
    scenario = random.choice(SCENARIOS)
    org = random.choice(ORG_NAMES)
    date = random_date()
    ip = random_safe_ip()
    domain = random_safe_domain()
    file_hash = random_hash()

    text = scenario["template"].format(
        org=org, date=date, ip=defang(ip), domain=defang(domain)
    )
    text += f" A related file hash was observed: {file_hash}."

    # Occasionally include a second, unrelated technique to add label noise
    # (realistic — reports are rarely perfectly clean single-scenario cases)
    techniques = list(scenario["techniques"])
    if random.random() < 0.15:
        extra_scenario = random.choice(SCENARIOS)
        candidate = random.choice(extra_scenario["techniques"])
        if candidate not in techniques:
            techniques.append(candidate)

    return {
        "report_id": f"RPT-{report_id:04d}",
        "title": f"{scenario['name'].replace('_', ' ').title()} — {org}",
        "source": random.choice(SOURCE_FEEDS),
        "tlp": random.choice(TLP_LEVELS),
        "date": date,
        "text": text,
        "iocs": {
            "ips": [ip],
            "domains": [domain],
            "hashes": [file_hash],
        },
        "attck_techniques": techniques,  # ground truth, used for model training/eval
        "scenario": scenario["name"],
    }


def generate_dataset(n_reports=250, output_path="data/raw/sample_cti_reports.jsonl"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ------------------------------------------------------------------
    # Deliberately inject a handful of "campaigns": groups of reports
    # that share the SAME specific C2 IP/domain, simulating multiple
    # victim organizations hit by the same coordinated threat actor
    # infrastructure. This is what makes campaign clustering (Lab 5)
    # meaningful — without shared infrastructure, there is nothing
    # genuine for the knowledge graph to cluster.
    # ------------------------------------------------------------------
    n_campaigns = 4
    reports_per_campaign = 4
    campaign_report_count = n_campaigns * reports_per_campaign

    reports = []
    report_id_counter = 1

    for campaign_num in range(n_campaigns):
        shared_scenario = random.choice(SCENARIOS)
        shared_ip = random_safe_ip()
        shared_domain = random_safe_domain()

        for _ in range(reports_per_campaign):
            org = random.choice(ORG_NAMES)
            date = random_date()
            file_hash = random_hash()

            text = shared_scenario["template"].format(
                org=org, date=date, ip=defang(shared_ip), domain=defang(shared_domain)
            )
            text += f" A related file hash was observed: {file_hash}."

            reports.append({
                "report_id": f"RPT-{report_id_counter:04d}",
                "title": f"{shared_scenario['name'].replace('_', ' ').title()} — {org}",
                "source": random.choice(SOURCE_FEEDS),
                "tlp": random.choice(TLP_LEVELS),
                "date": date,
                "text": text,
                "iocs": {
                    "ips": [shared_ip],
                    "domains": [shared_domain],
                    "hashes": [file_hash],
                },
                "attck_techniques": list(shared_scenario["techniques"]),
                "scenario": shared_scenario["name"],
                "campaign_id": f"CAMPAIGN-{campaign_num + 1}",  # ground truth, for verification
            })
            report_id_counter += 1

    # Remaining reports: independently random, as before
    for _ in range(n_reports - campaign_report_count):
        r = generate_report(report_id_counter)
        r["campaign_id"] = None
        reports.append(r)
        report_id_counter += 1

    with open(output_path, "w") as f:
        for r in reports:
            f.write(json.dumps(r) + "\n")

    return reports


if __name__ == "__main__":
    reports = generate_dataset()
    print(f"Generated {len(reports)} synthetic CTI reports -> data/raw/sample_cti_reports.jsonl")
