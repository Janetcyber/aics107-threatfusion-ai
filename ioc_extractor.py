"""
IOC Extraction, Normalization, and Safety Controls
=====================================================
Extracts indicators of compromise (IPs, domains, file hashes, CVE IDs)
from CTI report text.

Safety control (per lab requirement): indicators in report text are
stored and displayed in DEFANGED form (e.g. 192[.]0[.]2[.]59) at all
times. The `refang()` function exists ONLY to normalize an indicator
into a canonical string for internal matching/deduplication/graph-
linking purposes — it is never used to construct a clickable link,
make a network request, or otherwise interact with the indicator.
No code in this project ever visits, resolves, or connects to any
extracted indicator.
"""

import re
import json
import os

# ----------------------------------------------------------------------
# Regex patterns (operate on DEFANGED text, since that's what our
# reports contain)
# ----------------------------------------------------------------------
DEFANGED_IP_RE = re.compile(r'\b(\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\b')
DEFANGED_DOMAIN_RE = re.compile(r'\b([a-zA-Z0-9\-]+(?:-[a-zA-Z0-9]+)*)\[\.\](example|test|invalid)\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')


def refang(indicator):
    """
    Convert a defanged indicator to its canonical (non-bracketed) form
    for internal matching/deduplication ONLY.

    SAFETY NOTE: the output of this function must never be treated as
    a URL, hostname to resolve, or address to connect to. It is a text
    string used purely for graph node identity and IOC deduplication
    within this pipeline.
    """
    return indicator.replace("[.]", ".")


def defang(indicator):
    """Ensure an indicator is in safe, defanged display form."""
    if "[.]" in indicator:
        return indicator
    return indicator.replace(".", "[.]")


def extract_iocs_from_text(text):
    """Extract all IOC types from a single block of report text."""
    ips = [refang(f"{m.group(1)}[.]{m.group(2)}[.]{m.group(3)}[.]{m.group(4)}")
           for m in DEFANGED_IP_RE.finditer(text)]

    domains = [refang(f"{m.group(1)}[.]{m.group(2)}") for m in DEFANGED_DOMAIN_RE.finditer(text)]

    hashes = SHA256_RE.findall(text)
    cves = CVE_RE.findall(text)

    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "hashes": sorted(set(hashes)),
        "cves": sorted(set(cves)),
    }


def run_extraction(
    input_path="data/raw/sample_cti_reports.jsonl",
    output_path="data/processed/extracted_iocs.jsonl",
):
    """
    Run IOC extraction across every report in the corpus. Writes one
    JSON record per report to data/processed/, and returns basic
    before/after stats for verification.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    records = []
    with open(input_path) as f:
        for line in f:
            report = json.loads(line)
            extracted = extract_iocs_from_text(report["text"])

            records.append({
                "report_id": report["report_id"],
                "extracted_iocs": extracted,
                "ground_truth_iocs": report.get("iocs", {}),  # for verification only
            })

    with open(output_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # Verification stats: does extraction find at least the ground-truth IOCs?
    total_reports = len(records)
    reports_with_matched_ip = sum(
        1 for r in records
        if any(ip in r["extracted_iocs"]["ips"] for ip in r["ground_truth_iocs"].get("ips", []))
    )

    print(f"Processed {total_reports} reports.")
    print(f"Extracted IOCs written to {output_path}")
    print(f"Verification: {reports_with_matched_ip}/{total_reports} reports had their "
          f"known (ground-truth) IP correctly re-extracted from text.")

    return records


if __name__ == "__main__":
    run_extraction()
