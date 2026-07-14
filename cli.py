"""
ThreatFusion AI — Command Line Interface
==========================================
Usage:
    python -m threatfusion_ai.cli init-data
    python -m threatfusion_ai.cli train
    python -m threatfusion_ai.cli run-pipeline
    python -m threatfusion_ai.cli report --case-id RPT-0001
"""

import argparse
import os

from threatfusion_ai import data_generator


def cmd_init_data(args):
    print("Generating synthetic CTI report corpus...")
    reports = data_generator.generate_dataset(
        n_reports=args.n_reports,
        output_path="data/raw/sample_cti_reports.jsonl",
    )
    print(f"Done. {len(reports)} reports written to data/raw/sample_cti_reports.jsonl")

    # Ensure the full expected folder structure exists (per lab manual)
    for d in ["data/processed", "outputs/stix", "outputs/graphs", "outputs/reports"]:
        os.makedirs(d, exist_ok=True)
    print("Verified project folder structure (data/, outputs/, and subfolders).")


def cmd_train(args):
    from threatfusion_ai import attck_model
    attck_model.train_and_evaluate()


def cmd_run_pipeline(args):
    from threatfusion_ai import pipeline
    pipeline.run_full_pipeline()


def cmd_report(args):
    from threatfusion_ai import report_generator
    report_generator.generate_report_for_case(args.case_id)


def cmd_compare_weights(args):
    from threatfusion_ai import risk_scoring
    risk_scoring.compare_weight_configurations()


def build_parser():
    parser = argparse.ArgumentParser(prog="threatfusion_ai", description="ThreatFusion AI — Defensive CTI Fusion Pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-data", help="Generate the synthetic CTI report corpus")
    p_init.add_argument("--n-reports", type=int, default=250, help="Number of synthetic reports to generate")
    p_init.set_defaults(func=cmd_init_data)

    p_train = sub.add_parser("train", help="Train the baseline ATT&CK mapping classifier")
    p_train.set_defaults(func=cmd_train)

    p_pipeline = sub.add_parser("run-pipeline", help="Run the full CTI fusion pipeline")
    p_pipeline.set_defaults(func=cmd_run_pipeline)

    p_report = sub.add_parser("report", help="Generate an analyst report for a given case ID")
    p_report.add_argument("--case-id", type=str, required=True, help="Report ID or case identifier")
    p_report.set_defaults(func=cmd_report)

    p_compare = sub.add_parser("compare-weights", help="Compare default vs modified risk scoring weights")
    p_compare.set_defaults(func=cmd_compare_weights)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
