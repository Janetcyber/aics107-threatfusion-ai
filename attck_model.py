"""
Train the ATT&CK Mapping Model
=================================
Trains a baseline multi-label classifier that predicts which MITRE
ATT&CK techniques a CTI report describes, based on its text.

Approach: TF-IDF text vectorization + One-vs-Rest Logistic Regression
(one binary classifier per technique). This is a standard, explainable
baseline for multi-label text classification — appropriate for a
250-report training corpus, and easy to justify/defend versus a more
complex model that would need far more data to train reliably.
"""

import json
import os

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import f1_score, classification_report, precision_score, recall_score

SEED = 42


def load_reports(path="data/raw/sample_cti_reports.jsonl"):
    reports = []
    with open(path) as f:
        for line in f:
            reports.append(json.loads(line))
    return reports


def train_and_evaluate(
    input_path="data/raw/sample_cti_reports.jsonl",
    output_path="outputs/model_evaluation.txt",
):
    reports = load_reports(input_path)

    texts = [r["text"] for r in reports]
    labels = [r["attck_techniques"] for r in reports]

    mlb = MultiLabelBinarizer()
    y = mlb.fit_transform(labels)
    technique_names = mlb.classes_

    X_train_text, X_test_text, y_train, y_test, reports_train, reports_test = train_test_split(
        texts, y, reports, test_size=0.2, random_state=SEED
    )

    vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words="english")
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    model = OneVsRestClassifier(LogisticRegression(max_iter=1000, random_state=SEED))
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)

    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    macro_precision = precision_score(y_test, y_pred, average="macro", zero_division=0)
    macro_recall = recall_score(y_test, y_pred, average="macro", zero_division=0)

    report_text = classification_report(
        y_test, y_pred, target_names=technique_names, zero_division=0, digits=3
    )

    # ------------------------------------------------------------------
    # Error analysis: find specific false positives / weak predictions
    # ------------------------------------------------------------------
    error_examples = []
    for i in range(len(y_test)):
        true_techniques = set(mlb.inverse_transform(y_test[i:i+1])[0])
        pred_techniques = set(mlb.inverse_transform(y_pred[i:i+1])[0])

        false_positives = pred_techniques - true_techniques
        false_negatives = true_techniques - pred_techniques

        if false_positives or false_negatives:
            error_examples.append({
                "report_id": reports_test[i]["report_id"],
                "scenario": reports_test[i]["scenario"],
                "true_techniques": sorted(true_techniques),
                "predicted_techniques": sorted(pred_techniques),
                "false_positives": sorted(false_positives),
                "false_negatives": sorted(false_negatives),
            })

    # Write full evaluation file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("ThreatFusion AI — ATT&CK Mapping Model Evaluation\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Training corpus: {len(reports)} reports "
                f"({len(X_train_text)} train / {len(X_test_text)} test)\n")
        f.write(f"Technique vocabulary: {len(technique_names)} unique ATT&CK techniques\n\n")
        f.write(f"Macro Precision: {macro_precision:.3f}\n")
        f.write(f"Macro Recall:    {macro_recall:.3f}\n")
        f.write(f"Macro F1:        {macro_f1:.3f}\n\n")
        f.write("-" * 70 + "\n")
        f.write("PER-TECHNIQUE CLASSIFICATION REPORT\n")
        f.write("-" * 70 + "\n")
        f.write(report_text)
        f.write("\n" + "-" * 70 + "\n")
        f.write(f"ERROR ANALYSIS — {len(error_examples)} test reports with at least one "
                f"false positive or false negative\n")
        f.write("-" * 70 + "\n\n")

        for i, err in enumerate(error_examples[:10], 1):
            f.write(f"[{i}] Report {err['report_id']} (scenario: {err['scenario']})\n")
            f.write(f"    True techniques:      {err['true_techniques']}\n")
            f.write(f"    Predicted techniques: {err['predicted_techniques']}\n")
            if err["false_positives"]:
                f.write(f"    False positives: {err['false_positives']} "
                        f"(model over-predicted these)\n")
            if err["false_negatives"]:
                f.write(f"    False negatives: {err['false_negatives']} "
                        f"(model missed these)\n")
            f.write("\n")

    print(f"Model trained on {len(X_train_text)} reports, evaluated on {len(X_test_text)}.")
    print(f"Macro F1: {macro_f1:.3f} | Macro Precision: {macro_precision:.3f} | "
          f"Macro Recall: {macro_recall:.3f}")
    print(f"Full evaluation written to {output_path}")
    print(f"{len(error_examples)} test reports had at least one prediction error "
          f"(see {output_path} for details).")

    return {
        "macro_f1": macro_f1,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "error_examples": error_examples,
    }


if __name__ == "__main__":
    train_and_evaluate()


def predict_all_reports(input_path="data/raw/sample_cti_reports.jsonl"):
    """
    Train a model on the FULL corpus and predict ATT&CK techniques (with
    confidence) for every report. Used to build model-backed enriched case
    records for the knowledge graph (Lab 5) and downstream stages.

    Note: this is separate from train_and_evaluate(), which holds out a
    test set specifically to produce an honest, non-leaked performance
    evaluation (Lab 4's model_evaluation.txt). This function intentionally
    trains on everything, since its purpose is corpus enrichment, not
    performance measurement.
    """
    reports = load_reports(input_path)
    texts = [r["text"] for r in reports]
    labels = [r["attck_techniques"] for r in reports]

    mlb = MultiLabelBinarizer()
    y = mlb.fit_transform(labels)
    technique_names = mlb.classes_

    vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words="english")
    X = vectorizer.fit_transform(texts)

    model = OneVsRestClassifier(LogisticRegression(max_iter=1000, random_state=SEED))
    model.fit(X, y)

    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)

    predictions = {}
    for i, report in enumerate(reports):
        predicted_labels = mlb.inverse_transform(y_pred[i:i+1])[0]
        confidences = {
            technique_names[j]: round(float(y_proba[i][j]), 3)
            for j in range(len(technique_names))
            if technique_names[j] in predicted_labels
        }
        predictions[report["report_id"]] = {
            "predicted_techniques": list(predicted_labels),
            "confidences": confidences,
        }

    return predictions
