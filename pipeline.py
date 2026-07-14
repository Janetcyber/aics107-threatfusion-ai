"""
ThreatFusion AI — Full Pipeline Orchestrator
===============================================
Runs each stage of the CTI fusion pipeline in order. Stages are added
incrementally as each lab is completed:

  Lab 3: IOC extraction               <- implemented
  Lab 4: ATT&CK mapping (inference)   <- added later
  Lab 5: Knowledge graph + clustering <- added later
  Lab 6: Risk scoring                 <- added later
  Lab 7: STIX export                  <- added later
"""

from threatfusion_ai import ioc_extractor
from threatfusion_ai import knowledge_graph
from threatfusion_ai import risk_scoring


def run_full_pipeline():
    print("=" * 60)
    print("ThreatFusion AI — Running Pipeline")
    print("=" * 60)

    print("\n[Stage 1/3] IOC Extraction, Normalization, and Safety Controls")
    ioc_extractor.run_extraction()

    print("\n[Stage 2/3] Knowledge Graph and Campaign Clustering")
    knowledge_graph.run_knowledge_graph_stage()

    print("\n[Stage 3/3] Risk Scoring and Intelligence Prioritization")
    risk_scoring.run_risk_scoring()

    print("\nPipeline stage(s) complete.")


if __name__ == "__main__":
    run_full_pipeline()
