"""
threatfusion_ai.report_generator
Lab 9 - AI Analyst Report Generation

Design decision (documented for capstone report):
Reports are generated via deterministic templates populated from validated
pipeline data (Labs 4-6), not via a live generative model call. This follows
the course material's explicit guidance: "LLMs can draft intelligence
reports and summarize evidence, but they must cite the evidence records and
must not invent indicators or attribution." A template keyed to real
risk_score, predicted_techniques, and IOC fields cannot invent an indicator
that is not already in the pipeline's data - the tradeoff is stylistic
range, which is handled instead by three distinct templates (technical,
executive, detection-engineer) over the same underlying facts.

Case-ID mapping: the lab manual references LAB-ALPHA...LAB-ECHO as example
case IDs. This corpus's natural "case" unit is a campaign cluster from
Lab 5 (reports sharing IOCs). LAB-ALPHA/BRAVO/CHARLIE/DELTA/ECHO are mapped
to campaign_clusters.json cluster_id 1-5 respectively.
"""

from __future__ import annotations

import json
from pathlib import Path
from statistics import mean

ATTCK_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1027": "Obfuscated Files or Information",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1078": "Valid Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1486": "Data Encrypted for Impact",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1566.001": "Phishing: Spearphishing Attachment",
}

CASE_ID_TO_CLUSTER = {
    "LAB-ALPHA": 1,
    "LAB-BRAVO": 2,
    "LAB-CHARLIE": 3,
    "LAB-DELTA": 4,
    "LAB-ECHO": 5,
}


def technique_name(tid: str) -> str:
    return f"{tid} ({ATTCK_NAMES.get(tid, 'Unmapped technique - verify against current ATT&CK release')})"


def load_enriched_cases(path: str = "data/processed/enriched_cases.jsonl") -> dict:
    records = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        records[rec["report_id"]] = rec
    return records


def load_clusters(path: str = "outputs/campaign_clusters.json") -> dict:
    data = json.loads(Path(path).read_text())
    return {c["cluster_id"]: c for c in data["clusters"]}


def build_case(case_id: str, cases: dict, clusters: dict) -> dict:
    cluster_id = CASE_ID_TO_CLUSTER.get(case_id)
    if cluster_id is None or cluster_id not in clusters:
        raise ValueError(
            f"Unknown case ID '{case_id}'. Valid: {list(CASE_ID_TO_CLUSTER)}"
        )
    cluster = clusters[cluster_id]
    report_ids = cluster["report_ids"]
    reports = [cases[rid] for rid in report_ids if rid in cases]

    if not reports:
        raise ValueError(f"No enriched case data found for cluster {cluster_id} report IDs {report_ids}")

    all_techniques = sorted({t for r in reports for t in r.get("predicted_techniques", [])})
    avg_risk = round(mean(r["risk_score"] for r in reports), 1)
    max_report = max(reports, key=lambda r: r["risk_score"])
    severities = [r["severity"] for r in reports]
    severity_counts = {s: severities.count(s) for s in set(severities)}

    all_ips = sorted({ip for r in reports for ip in r["iocs"].get("ips", [])})
    all_domains = sorted({d for r in reports for d in r["iocs"].get("domains", [])})
    all_hashes = sorted({h for r in reports for h in r["iocs"].get("hashes", [])})

    avg_confidence = round(
        mean(
            conf
            for r in reports
            for conf in r.get("technique_confidences", {}).values()
        ),
        3,
    ) if any(r.get("technique_confidences") for r in reports) else 0.0

    return {
        "case_id": case_id,
        "cluster_id": cluster_id,
        "report_count": len(reports),
        "report_ids": report_ids,
        "all_techniques": all_techniques,
        "avg_risk_score": avg_risk,
        "max_risk_report": max_report,
        "severity_counts": severity_counts,
        "all_ips": all_ips,
        "all_domains": all_domains,
        "all_hashes": all_hashes,
        "avg_confidence": avg_confidence,
    }


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

def render_technical(c: dict) -> str:
    techniques_block = "\n".join(f"- {technique_name(t)}" for t in c["all_techniques"])
    ips_block = "\n".join(f"- {ip}" for ip in c["all_ips"]) or "- None observed"
    domains_block = "\n".join(f"- {d}" for d in c["all_domains"]) or "- None observed"
    hashes_block = "\n".join(f"- {h}" for h in c["all_hashes"]) or "- None observed"
    sev_block = ", ".join(f"{k}: {v}" for k, v in c["severity_counts"].items())

    return f"""# Intelligence Report: {c['case_id']}
**Report type:** Technical / SOC analyst
**Case cluster:** {c['cluster_id']} (source: Lab 5 knowledge graph, IOC-based clustering)
**Reports in case:** {c['report_count']} ({', '.join(c['report_ids'])})

## Summary
This case aggregates {c['report_count']} related CTI reports sharing indicators of compromise,
clustered by the Lab 5 knowledge graph. Average risk score across the case is
{c['avg_risk_score']}/100. Severity distribution: {sev_block}.

## ATT&CK Techniques Observed
{techniques_block}

## Indicators of Compromise
### IP Addresses
{ips_block}

### Domains
{domains_block}

### File Hashes (SHA-256)
{hashes_block}

## Highest-Risk Report in Case
Report {c['max_risk_report']['report_id']} carries the highest individual risk score
in this case at {c['max_risk_report']['risk_score']}/100 (severity: {c['max_risk_report']['severity']}).
Risk breakdown: technique component {c['max_risk_report']['risk_breakdown']['technique_component']},
confidence component {c['max_risk_report']['risk_breakdown']['confidence_component']},
IOC volume component {c['max_risk_report']['risk_breakdown']['ioc_component']}.

## Confidence
Average ATT&CK mapping confidence across this case: {c['avg_confidence']} (model: TF-IDF +
OneVsRest Logistic Regression, macro-F1 0.970 on held-out test set per Lab 4 evaluation).
Confidence reflects classifier certainty on report text, not independently verified
adversary behavior. IOC-based clustering (Lab 5) reflects shared infrastructure only,
not confirmed common actor attribution.

## Limitations
- Source corpus is synthetic; IOCs use RFC 5737 documentation-space addresses and
  .invalid domains and will not resolve against real-world threat feeds.
- Live external enrichment (Lab 8) was not performed pending instructor authorization;
  no third-party corroboration of these indicators exists.
- ATT&CK mapping is model-recommended and requires analyst validation before
  operational use, per course guidance.

## Recommended Defensive Actions
- Validate presence of the listed IOCs against internal SIEM/EDR telemetry.
- Prioritize detection engineering for the highest-confidence techniques listed above.
- Escalate the highest-risk report ({c['max_risk_report']['report_id']}) for manual analyst review
  before any containment action.
"""


def render_executive(c: dict) -> str:
    sev_block = ", ".join(f"{k}: {v}" for k, v in c["severity_counts"].items())
    top_techniques = ", ".join(ATTCK_NAMES.get(t, t) for t in c["all_techniques"][:3])
    return f"""# Executive Briefing: {c['case_id']}

## What happened
Our threat intelligence pipeline identified a cluster of {c['report_count']} related
security reports sharing common attack infrastructure. The average risk score for
this activity is {c['avg_risk_score']} out of 100, with a severity breakdown of {sev_block}.

## Why it matters
The observed activity is consistent with techniques such as {top_techniques}. These
represent credible risk to affected systems if not addressed; the highest-risk single
incident in this cluster scored {c['max_risk_report']['risk_score']}/100.

## What we recommend
1. SOC and detection engineering teams should validate the technical indicators
   associated with this case against internal monitoring.
2. No external sharing or law-enforcement escalation is recommended at this time;
   this intelligence has not yet been corroborated against live external threat feeds.
3. This briefing should be reviewed alongside the accompanying technical report
   before any resourcing decision is made.

## Confidence and limitations
This assessment is machine-assisted and analyst-reviewable, not analyst-verified.
Treat as a prioritization input, not a final determination.
"""


def render_detection_engineer(c: dict) -> str:
    techniques_block = "\n".join(
        f"- **{technique_name(t)}** — confidence signal available in technique_confidences; "
        f"build/validate detection logic covering this technique's standard data sources."
        for t in c["all_techniques"]
    )
    ips_block = ", ".join(c["all_ips"]) or "none"
    domains_block = ", ".join(c["all_domains"]) or "none"
    hashes_block = "\n".join(c["all_hashes"]) or "none"

    return f"""# Detection Engineering Brief: {c['case_id']}

## Case scope
{c['report_count']} reports, cluster {c['cluster_id']}, avg risk {c['avg_risk_score']}/100.

## Techniques requiring detection coverage
{techniques_block}

## Raw indicators for watchlist / allowlist exclusion testing
- IPs: {ips_block}
- Domains: {domains_block}
- Hashes:
{hashes_block}

## Notes for detection authors
- These IOCs are synthetic (course dataset) and must NOT be deployed to production
  blocklists; use only to validate parsing/matching logic in a lab SIEM instance.
- Confidence scores per technique are classifier-derived (Lab 4 model); treat sub-0.85
  confidence techniques as lower priority for immediate rule authorship.
- Recommend building detections against technique behavior (process lineage, command
  line patterns) rather than these specific IOC values, since indicators are the most
  perishable layer of the pyramid of pain.
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Lab 9 - generate analyst reports")
    parser.add_argument("--case-id", required=True, help="e.g. LAB-ALPHA")
    parser.add_argument("--variant", choices=["technical", "executive", "detection", "all"], default="technical")
    parser.add_argument("--cases-file", default="data/processed/enriched_cases.jsonl")
    parser.add_argument("--clusters-file", default="outputs/campaign_clusters.json")
    parser.add_argument("--outdir", default="outputs/reports")
    args = parser.parse_args()

    cases = load_enriched_cases(args.cases_file)
    clusters = load_clusters(args.clusters_file)
    case = build_case(args.case_id, cases, clusters)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    variants = {
        "technical": ("000_intel_report", render_technical),
        "executive": ("001_executive_brief", render_executive),
        "detection": ("002_detection_brief", render_detection_engineer),
    }

    to_render = variants.items() if args.variant == "all" else [(args.variant, variants[args.variant])]

    for _, (suffix, render_fn) in to_render:
        content = render_fn(case)
        out_path = outdir / f"{args.case_id}-{suffix}.md"
        out_path.write_text(content)
        print(f"Written: {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
