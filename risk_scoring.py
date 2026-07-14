"""
Risk Scoring and Intelligence Prioritization
================================================
Computes a 0-100 risk score for each enriched case, combining:
  1. Technique criticality  — how severe are the mapped ATT&CK techniques?
  2. Model confidence       — how confident was the classifier in its mapping?
  3. IOC volume             — how much corroborating indicator evidence exists?

Weights are exposed as a configuration dict (DEFAULT_WEIGHTS) so they can
be modified and compared, per the lab's "review scoring function, modify
weights, compare outputs" requirement.
"""

import json

# ----------------------------------------------------------------------
# Technique criticality reference table
# (Higher = more severe/urgent if seen in an environment)
# ----------------------------------------------------------------------
TECHNIQUE_CRITICALITY = {
    "T1486": 10,       # Data Encrypted for Impact (ransomware) — highest severity
    "T1003": 9,        # OS Credential Dumping
    "T1078": 8,        # Valid Accounts (compromised credentials in active use)
    "T1548": 8,        # Abuse Elevation Control Mechanism
    "T1041": 8,        # Exfiltration Over C2 Channel
    "T1110": 7,        # Brute Force
    "T1071.001": 6,    # Application Layer Protocol (C2)
    "T1053.005": 6,    # Scheduled Task/Job
    "T1105": 6,        # Ingress Tool Transfer
    "T1566.001": 6,    # Phishing: Spearphishing Attachment
    "T1059.001": 5,    # PowerShell
    "T1059.003": 5,    # Windows Command Shell
    "T1027": 4,        # Obfuscated Files or Information
    "T1046": 3,        # Network Service Discovery (reconnaissance, lower urgency)
}

DEFAULT_WEIGHTS = {
    "technique_criticality": 0.75,
    "model_confidence": 0.15,
    "ioc_volume": 0.10,
}


def compute_risk_score(case, weights=None):
    """
    Compute a 0-100 risk score for a single enriched case.

    Returns (score, severity_label, breakdown_dict) so the reasoning
    behind the number is always inspectable, not just the final figure.
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    techniques = case.get("predicted_techniques", [])
    confidences = case.get("technique_confidences", {})
    iocs = case.get("iocs", {})

    # --- Technique criticality component: AVERAGE criticality across
    # mapped techniques, scaled to 0-100. Using the average (rather than
    # blending in the max) keeps this the most discriminating factor —
    # a report with one critical + several low-severity techniques scores
    # meaningfully differently from a report with several critical ones.
    if techniques:
        crit_scores = [TECHNIQUE_CRITICALITY.get(t, 5) for t in techniques]
        technique_component = (sum(crit_scores) / len(crit_scores)) * 10
    else:
        technique_component = 0

    # --- Model confidence component (average confidence -> 0-100) ---
    if confidences:
        avg_confidence = sum(confidences.values()) / len(confidences)
        confidence_component = avg_confidence * 100
    else:
        confidence_component = 0

    # --- IOC volume component (more corroborating indicators -> higher score, capped) ---
    ioc_count = sum(len(iocs.get(k, [])) for k in ["ips", "domains", "hashes"])
    ioc_component = min(ioc_count * 20, 100)  # 5+ IOCs maxes this out

    score = (
        technique_component * weights["technique_criticality"]
        + confidence_component * weights["model_confidence"]
        + ioc_component * weights["ioc_volume"]
    )
    score = round(min(score, 100), 1)

    if score >= 68:
        severity = "Critical"
    elif score >= 52:
        severity = "High"
    elif score >= 36:
        severity = "Medium"
    else:
        severity = "Low"

    breakdown = {
        "technique_component": round(technique_component, 1),
        "confidence_component": round(confidence_component, 1),
        "ioc_component": round(ioc_component, 1),
        "weights_used": weights,
    }

    return score, severity, breakdown


def run_risk_scoring(
    enriched_cases_path="data/processed/enriched_cases.jsonl",
    weights=None,
):
    """Apply risk scoring to every case and rewrite the enriched cases file."""
    cases = []
    with open(enriched_cases_path) as f:
        for line in f:
            cases.append(json.loads(line))

    for case in cases:
        score, severity, breakdown = compute_risk_score(case, weights)
        case["risk_score"] = score
        case["severity"] = severity
        case["risk_breakdown"] = breakdown

    with open(enriched_cases_path, "w") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")

    severity_counts = {}
    for c in cases:
        severity_counts[c["severity"]] = severity_counts.get(c["severity"], 0) + 1

    print(f"Risk scoring applied to {len(cases)} cases.")
    print(f"Severity distribution: {severity_counts}")
    print(f"Updated {enriched_cases_path} with risk_score, severity, and risk_breakdown fields.")

    return cases


def compare_weight_configurations(enriched_cases_path="data/processed/enriched_cases.jsonl"):
    """
    Lab 6 deliverable: compare original vs modified scoring weights.
    Modified config: prioritize technique criticality even more heavily
    (e.g. an organization that considers destructive/credential-theft
    techniques far more urgent than volume of corroborating IOCs).
    """
    modified_weights = {
        "technique_criticality": 0.90,
        "model_confidence": 0.06,
        "ioc_volume": 0.04,
    }

    cases = []
    with open(enriched_cases_path) as f:
        for line in f:
            cases.append(json.loads(line))

    results = []
    for case in cases:
        default_score, default_sev, _ = compute_risk_score(case, DEFAULT_WEIGHTS)
        mod_score, mod_sev, _ = compute_risk_score(case, modified_weights)
        results.append((case["report_id"], default_score, default_sev, mod_score, mod_sev))

    changed = [r for r in results if r[2] != r[4]]
    unchanged_sample = [r for r in results if r[2] == r[4]][:5]

    print(f"{'Report ID':<12} {'Default Score':<15} {'Default Sev.':<14} "
          f"{'Modified Score':<16} {'Modified Sev.':<14} {'Changed?'}")
    print("-" * 85)

    print(f"\n-- Cases where severity CHANGED ({len(changed)} of {len(results)} total) --")
    for r in changed[:10]:
        print(f"{r[0]:<12} {r[1]:<15} {r[2]:<14} {r[3]:<16} {r[4]:<14} YES")

    print(f"\n-- Sample of cases where severity did NOT change --")
    for r in unchanged_sample:
        print(f"{r[0]:<12} {r[1]:<15} {r[2]:<14} {r[3]:<16} {r[4]:<14} no")

    print(f"\nSummary: {len(changed)}/{len(results)} cases changed severity tier under "
          f"the modified weighting.")
    print(f"Modified weights heavily favor technique_criticality (0.90) over "
          f"model_confidence (0.06) and ioc_volume (0.04), reflecting an organization "
          f"that treats the nature of the attack technique as the dominant risk factor, "
          f"largely disregarding how many corroborating indicators were found or how "
          f"confident the model was in its technique mapping.")


if __name__ == "__main__":
    run_risk_scoring()
