"""
threatfusion_ai.embedding_recommender
Lab 10 - Advanced Extension: Embedding-Based ATT&CK Recommender

Design decision (documented for capstone report):
The lab manual specifies sentence-transformers "if resources allow." VM
resource check (df -h, free -h) showed 4.2GB free disk (85% used) and only
5.8GB total RAM allocated - below the course's own stated 8GB minimum. A
torch/sentence-transformers install was judged too risky to attempt reliably
in this environment, so this module uses TF-IDF + cosine similarity against
short canonical ATT&CK technique descriptions as a resource-light stand-in
for dense semantic embeddings.

Methodological limitation, stated plainly: TF-IDF is a lexical (bag-of-words)
representation, not a semantic one. It will only recognize similarity where
vocabulary overlaps. A true embedding model (e.g. all-MiniLM-L6-v2) would be
expected to generalize better across paraphrased report language. Because
this course's Lab 4 baseline classifier is ALSO TF-IDF-based, a degree of
convergence between "baseline" and "embedding" columns here is expected and
is itself part of the finding, not a sign the comparison is broken.

Three-way comparison:
  - baseline:  Lab 4 trained classifier predictions (predicted_techniques)
  - embedding: TF-IDF cosine similarity vs technique description corpus (this module)
  - human:     attck_techniques ground-truth field injected by the Lab 1
               synthetic data generator at report authoring time
"""

from __future__ import annotations

import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Short canonical descriptions - used as the "semantic reference corpus"
# that report text is compared against. Wording drawn from MITRE ATT&CK
# public technique summaries, paraphrased for brevity.
TECHNIQUE_DESCRIPTIONS = {
    "T1003": "adversary dumps credentials from operating system memory or files to obtain account login information",
    "T1027": "adversary obfuscates or encodes files and payloads to evade detection and analysis",
    "T1041": "adversary exfiltrates stolen data over an existing command and control communication channel",
    "T1046": "adversary scans and discovers network services running on remote systems to identify targets",
    "T1053.005": "adversary abuses the Windows Task Scheduler to establish persistence or execute code on a schedule",
    "T1059.001": "adversary uses PowerShell to execute commands, scripts, and payloads on the system",
    "T1059.003": "adversary uses the Windows command shell cmd.exe to execute commands and scripts",
    "T1071.001": "adversary communicates using web protocols like HTTP or HTTPS to blend command and control with normal traffic",
    "T1078": "adversary obtains and abuses valid account credentials to gain and maintain access to systems",
    "T1105": "adversary transfers tools or files from an external system onto the compromised host",
    "T1110": "adversary attempts repeated login guesses to brute force account passwords",
    "T1486": "adversary encrypts files on target systems to disrupt availability, typically for ransom",
    "T1548": "adversary abuses mechanisms to bypass or elevate access control and gain higher privileges",
    "T1566.001": "adversary sends a spearphishing email with a malicious attachment to gain initial access",
}


def load_raw_reports(path: str = "data/raw/sample_cti_reports.jsonl") -> dict:
    reports = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        reports[rec["report_id"]] = rec
    return reports


def load_enriched_cases(path: str = "data/processed/enriched_cases.jsonl") -> dict:
    cases = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        cases[rec["report_id"]] = rec
    return cases


class EmbeddingRecommender:
    """TF-IDF cosine-similarity recommender over the technique description corpus."""

    def __init__(self):
        self.technique_ids = list(TECHNIQUE_DESCRIPTIONS.keys())
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.technique_matrix = self.vectorizer.fit_transform(
            [TECHNIQUE_DESCRIPTIONS[t] for t in self.technique_ids]
        )

    def recommend(self, report_text: str, top_k: int = 2) -> list[tuple[str, float]]:
        vec = self.vectorizer.transform([report_text])
        sims = cosine_similarity(vec, self.technique_matrix)[0]
        ranked = sorted(zip(self.technique_ids, sims), key=lambda x: -x[1])
        return ranked[:top_k]


def overlap_label(baseline: set, embedding: set, human: set) -> str:
    all_agree = baseline & embedding & human
    if all_agree:
        return "full_agreement"
    if (baseline & human) or (embedding & human):
        return "partial_agreement"
    return "no_agreement"


def build_comparison(report_ids: list[str], raw: dict, cases: dict, recommender: EmbeddingRecommender) -> list[dict]:
    rows = []
    for rid in report_ids:
        if rid not in raw or rid not in cases:
            continue
        report_text = raw[rid].get("text", "")
        human_set = set(raw[rid].get("attck_techniques", []))
        baseline_set = set(cases[rid].get("predicted_techniques", []))
        embed_ranked = recommender.recommend(report_text, top_k=2)
        embed_set = {t for t, score in embed_ranked}

        rows.append({
            "report_id": rid,
            "human_judgment": sorted(human_set),
            "baseline_classifier": sorted(baseline_set),
            "embedding_recommender": sorted(embed_set),
            "embedding_scores": {t: round(float(s), 3) for t, s in embed_ranked},
            "agreement": overlap_label(baseline_set, embed_set, human_set),
        })
    return rows


def render_markdown_table(rows: list[dict]) -> str:
    lines = [
        "# Lab 10 - Baseline vs Embedding Recommender vs Human Judgment",
        "",
        "Methodology: baseline = Lab 4 TF-IDF/LogisticRegression classifier predictions. "
        "embedding = TF-IDF cosine similarity vs canonical ATT&CK technique descriptions "
        "(resource-light substitute for sentence-transformers - see module docstring for rationale). "
        "human = ground-truth attck_techniques field from the Lab 1 synthetic data generator.",
        "",
        "| Report | Human Judgment | Baseline Classifier | Embedding Recommender | Agreement |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['report_id']} | {', '.join(r['human_judgment']) or '-'} "
            f"| {', '.join(r['baseline_classifier']) or '-'} "
            f"| {', '.join(r['embedding_recommender']) or '-'} "
            f"| {r['agreement']} |"
        )

    total = len(rows)
    full = sum(1 for r in rows if r["agreement"] == "full_agreement")
    partial = sum(1 for r in rows if r["agreement"] == "partial_agreement")
    none_ = sum(1 for r in rows if r["agreement"] == "no_agreement")

    lines += [
        "",
        "## Aggregate agreement",
        f"- Full agreement (all three match): {full}/{total} ({100*full/total:.1f}%)" if total else "- No rows",
        f"- Partial agreement (baseline or embedding matches human): {partial}/{total} ({100*partial/total:.1f}%)" if total else "",
        f"- No agreement: {none_}/{total} ({100*none_/total:.1f}%)" if total else "",
        "",
        "## Interpretation note",
        "Both baseline and embedding columns use TF-IDF representations, so convergence "
        "between them is expected and does not by itself validate semantic generalization. "
        "A true dense-embedding model (sentence-transformers) would be the correct next "
        "step to test generalization on paraphrased report language; this was not run in "
        "this environment due to VM resource constraints (see module docstring).",
    ]
    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Lab 10 - embedding-style ATT&CK recommender comparison")
    parser.add_argument("--raw", default="data/raw/sample_cti_reports.jsonl")
    parser.add_argument("--cases", default="data/processed/enriched_cases.jsonl")
    parser.add_argument("--sample-size", type=int, default=20)
    parser.add_argument("--output", default="outputs/reports/lab10_comparison.md")
    args = parser.parse_args()

    raw = load_raw_reports(args.raw)
    cases = load_enriched_cases(args.cases)
    recommender = EmbeddingRecommender()

    sample_ids = sorted(raw.keys())[: args.sample_size]
    rows = build_comparison(sample_ids, raw, cases, recommender)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_markdown_table(rows))

    print(f"Compared {len(rows)} reports.")
    agreement_counts = {}
    for r in rows:
        agreement_counts[r["agreement"]] = agreement_counts.get(r["agreement"], 0) + 1
    print(f"Agreement breakdown: {agreement_counts}")
    print(f"Comparison table written to: {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
