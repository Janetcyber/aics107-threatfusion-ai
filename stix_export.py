"""
STIX 2.1-Style Export and Platform Mapping
==============================================
Converts enriched case records (IOCs + model-mapped ATT&CK techniques)
into a STIX 2.1 Bundle: Indicator objects for each IOC, AttackPattern
objects for each mapped technique, and a Report object per case tying
them together. This is the standard format used to share structured
threat intelligence with platforms like MISP and OpenCTI.
"""

import json
import os

import stix2


def ioc_to_stix_pattern(ioc, ioc_type):
    """Build a STIX pattern string for a given indicator."""
    if ioc_type == "ips":
        return f"[ipv4-addr:value = '{ioc}']"
    elif ioc_type == "domains":
        return f"[domain-name:value = '{ioc}']"
    elif ioc_type == "hashes":
        return f"[file:hashes.'SHA-256' = '{ioc}']"
    return None


# Cache of AttackPattern STIX objects so each technique is only defined once,
# even though it appears across many reports (avoids duplicate objects in
# the bundle).
_attack_pattern_cache = {}


def get_or_create_attack_pattern(technique_id, technique_name=None):
    if technique_id in _attack_pattern_cache:
        return _attack_pattern_cache[technique_id]

    ap = stix2.AttackPattern(
        name=technique_name or technique_id,
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }
        ],
    )
    _attack_pattern_cache[technique_id] = ap
    return ap


def build_stix_bundle(
    enriched_cases_path="data/processed/enriched_cases.jsonl",
    raw_reports_path="data/raw/sample_cti_reports.jsonl",
    output_path="outputs/stix/threatfusion_bundle.json",
):
    _attack_pattern_cache.clear()

    # Load raw reports for title/date/TLP metadata not present in enriched_cases
    raw_reports = {}
    with open(raw_reports_path) as f:
        for line in f:
            r = json.loads(line)
            raw_reports[r["report_id"]] = r

    enriched_cases = []
    with open(enriched_cases_path) as f:
        for line in f:
            enriched_cases.append(json.loads(line))

    all_objects = []

    for case in enriched_cases:
        report_id = case["report_id"]
        raw = raw_reports.get(report_id, {})

        # --- Indicator objects for this case's IOCs ---
        indicator_refs = []
        for ioc_type in ["ips", "domains", "hashes"]:
            for ioc in case["iocs"].get(ioc_type, []):
                pattern = ioc_to_stix_pattern(ioc, ioc_type)
                if pattern is None:
                    continue
                indicator = stix2.Indicator(
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=raw.get("date", "2026-01-01") + "T00:00:00Z",
                    labels=["malicious-activity"],
                    indicator_types=["malicious-activity"],
                )
                all_objects.append(indicator)
                indicator_refs.append(indicator.id)

        # --- AttackPattern objects for this case's mapped techniques ---
        attack_pattern_refs = []
        for technique in case["predicted_techniques"]:
            ap = get_or_create_attack_pattern(technique)
            attack_pattern_refs.append(ap.id)

        # --- Report object tying everything together ---
        report_obj = stix2.Report(
            name=raw.get("title", report_id),
            description=raw.get("text", "")[:500],
            published=raw.get("date", "2026-01-01") + "T00:00:00Z",
            report_types=["threat-report"],
            object_refs=indicator_refs + attack_pattern_refs,
            labels=[case.get("severity", "Unknown")],
            confidence=int(
                (sum(case.get("technique_confidences", {}).values()) /
                 max(len(case.get("technique_confidences", {})), 1)) * 100
            ) if case.get("technique_confidences") else 50,
        )
        all_objects.append(report_obj)

    # Add the (deduplicated) AttackPattern objects
    all_objects.extend(_attack_pattern_cache.values())

    bundle = stix2.Bundle(objects=all_objects, allow_custom=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))

    n_indicators = sum(1 for o in all_objects if o.type == "indicator")
    n_attack_patterns = len(_attack_pattern_cache)
    n_reports = sum(1 for o in all_objects if o.type == "report")

    print(f"STIX bundle built: {len(all_objects)} total objects "
          f"({n_indicators} indicators, {n_attack_patterns} attack-patterns, "
          f"{n_reports} reports)")
    print(f"Bundle written to {output_path}")

    return bundle


if __name__ == "__main__":
    build_stix_bundle()
