"""
Build a Threat Knowledge Graph
=================================
Merges extracted IOCs (Lab 3) with model-predicted ATT&CK techniques
(Lab 4's model, applied corpus-wide) into enriched case records, builds
a graph linking reports <-> IOCs <-> techniques, and identifies
campaign clusters: groups of reports that likely represent the same
coordinated activity because they share indicators.
"""

import json
import os
import networkx as nx

from threatfusion_ai import attck_model


def build_enriched_cases(
    extracted_iocs_path="data/processed/extracted_iocs.jsonl",
    output_path="data/processed/enriched_cases.jsonl",
):
    """Combine extracted IOCs with model-backed ATT&CK predictions per report."""
    predictions = attck_model.predict_all_reports()

    enriched = []
    with open(extracted_iocs_path) as f:
        for line in f:
            record = json.loads(line)
            report_id = record["report_id"]
            pred = predictions.get(report_id, {"predicted_techniques": [], "confidences": {}})

            enriched.append({
                "report_id": report_id,
                "iocs": record["extracted_iocs"],
                "predicted_techniques": pred["predicted_techniques"],
                "technique_confidences": pred["confidences"],
                "risk_score": None,  # filled in Lab 6
            })

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        for e in enriched:
            f.write(json.dumps(e) + "\n")

    print(f"Enriched {len(enriched)} cases -> {output_path}")
    return enriched


def build_graph(enriched_cases, graph_output_path="outputs/graphs/threat_knowledge_graph.graphml"):
    """
    Build a graph with three node types:
      - report nodes   (id: report_id)
      - IOC nodes       (id: the indicator itself, typed ip/domain/hash)
      - technique nodes (id: ATT&CK technique ID)

    Edges: report -> IOC ("mentions"), report -> technique ("mapped_to").
    """
    G = nx.Graph()

    for case in enriched_cases:
        report_node = case["report_id"]
        G.add_node(report_node, node_type="report")

        for ioc_type in ["ips", "domains", "hashes"]:
            for ioc in case["iocs"].get(ioc_type, []):
                G.add_node(ioc, node_type="ioc", ioc_type=ioc_type)
                G.add_edge(report_node, ioc, relation="mentions")

        for tech in case["predicted_techniques"]:
            confidence = case["technique_confidences"].get(tech, None)
            G.add_node(tech, node_type="technique")
            G.add_edge(report_node, tech, relation="mapped_to", confidence=confidence)

    os.makedirs(os.path.dirname(graph_output_path), exist_ok=True)
    nx.write_graphml(G, graph_output_path)

    print(f"Knowledge graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print(f"Graph written to {graph_output_path}")

    return G


def find_campaign_clusters(G, min_reports_per_cluster=2):
    """
    Identify campaign clusters: groups of reports connected via SHARED
    INDICATORS ONLY (IPs, domains, hashes) — not shared techniques.

    Rationale: technique overlap is a weak clustering signal, since many
    unrelated reports of the same general attack type (e.g. all phishing
    reports) legitimately share the same 2-4 techniques without being
    part of the same coordinated campaign. Shared specific infrastructure
    (the same C2 IP or domain appearing in multiple reports) is a much
    stronger, more specific signal of genuine campaign relatedness.
    """
    report_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "report"]

    report_graph = nx.Graph()
    report_graph.add_nodes_from(report_nodes)

    for shared_node in G.nodes():
        if G.nodes[shared_node].get("node_type") == "ioc":
            neighbors = [n for n in G.neighbors(shared_node) if n in report_nodes]
            for i in range(len(neighbors)):
                for j in range(i + 1, len(neighbors)):
                    if report_graph.has_edge(neighbors[i], neighbors[j]):
                        report_graph[neighbors[i]][neighbors[j]]["shared_count"] += 1
                    else:
                        report_graph.add_edge(neighbors[i], neighbors[j], shared_count=1)

    clusters = []
    for component in nx.connected_components(report_graph):
        if len(component) >= min_reports_per_cluster:
            clusters.append(sorted(component))

    clusters.sort(key=len, reverse=True)
    return clusters


def run_knowledge_graph_stage():
    enriched_cases = build_enriched_cases()
    G = build_graph(enriched_cases)
    clusters = find_campaign_clusters(G)

    cluster_output = {
        "total_clusters": len(clusters),
        "clusters": [
            {"cluster_id": i + 1, "report_count": len(c), "report_ids": c}
            for i, c in enumerate(clusters)
        ],
    }

    os.makedirs("outputs", exist_ok=True)
    with open("outputs/campaign_clusters.json", "w") as f:
        json.dump(cluster_output, f, indent=2)

    print(f"Identified {len(clusters)} campaign cluster(s) "
          f"(reports sharing IOCs or techniques).")
    print("Cluster summary written to outputs/campaign_clusters.json")

    return G, clusters


if __name__ == "__main__":
    run_knowledge_graph_stage()
