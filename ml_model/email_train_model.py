"""Train and evaluate the email phishing text classifier.

Run from the repository root:
    python ml_model/email_train_model.py

Expected private/local dataset:
    datasets/emails/phishing_email.csv
with columns: text_combined, label

The TF-IDF vocabulary is fitted on the training split only to prevent
vocabulary leakage from the held-out test data.
"""
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "datasets" / "emails" / "phishing_email.csv"
MODEL_DIR = ROOT / "ml_model"
OUTPUT_DIR = ROOT / "evaluations" / "email"
RANDOM_STATE = 42
TEST_SIZE = 0.20


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}. "
            "See docs/MODELS_AND_DATASETS.md for expected data and licensing notes."
        )

    df = pd.read_csv(DATASET_PATH)
    required = {"text_combined", "label"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    df = df[["text_combined", "label"]].dropna()
    df["text_combined"] = df["text_combined"].astype(str).str.strip()
    df = df[df["text_combined"].ne("")]
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    labels = set(df["label"].unique())
    if labels != {0, 1}:
        raise ValueError(
            "Expected binary labels 0 (safe) and 1 (phishing); "
            f"found: {sorted(labels)}"
        )
    if df["label"].value_counts().min() < 2:
        raise ValueError("Each class needs at least two rows for a stratified split.")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text_combined"],
        df["label"],
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["label"],
    )

    # Fit vocabulary on training data only. Never fit on the held-out test set.
    vectorizer = TfidfVectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    class_order = list(model.classes_)
    phishing_index = class_order.index(1)
    y_prob = model.predict_proba(X_test_vec)[:, phishing_index]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=1, zero_division=0),
        "recall": recall_score(y_test, y_pred, pos_label=1, zero_division=0),
        "f1": f1_score(y_test, y_pred, pos_label=1, zero_division=0),
    }
    report = classification_report(
        y_test, y_pred, labels=[0, 1],
        target_names=["Safe", "Phishing"], zero_division=0
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Keep the separate model/vectorizer files expected by analyzer.services.
    joblib.dump(model, MODEL_DIR / "email_model.pkl")
    joblib.dump(vectorizer, MODEL_DIR / "email_vectorizer.pkl")

    metrics_text = [
        "EMAIL MODEL EVALUATION",
        f"Dataset rows after cleaning: {len(df)}",
        f"Training rows: {len(X_train)}",
        f"Test rows: {len(X_test)}",
        f"Random state: {RANDOM_STATE}",
        f"Test size: {TEST_SIZE}",
        "TF-IDF fit: training split only",
        "",
        f"Accuracy  : {metrics['accuracy'] * 100:.2f}%",
        f"Precision : {metrics['precision'] * 100:.2f}%",
        f"Recall    : {metrics['recall'] * 100:.2f}%",
        f"F1 Score  : {metrics['f1'] * 100:.2f}%",
        "",
        "CLASSIFICATION REPORT",
        report,
    ]
    (OUTPUT_DIR / "email_metrics.txt").write_text(
        "\n".join(metrics_text), encoding="utf-8"
    )

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Safe", "Phishing"],
        yticklabels=["Safe", "Phishing"],
    )
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Email Confusion Matrix")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "email_confusion_matrix.png", dpi=150)
    plt.close()

    fpr, tpr, _ = roc_curve(y_test, y_prob, pos_label=1)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.3f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Email ROC Curve")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "email_roc_curve.png", dpi=150)
    plt.close()

    print("\n".join(metrics_text))
    print(f"\nSaved model artifacts to: {MODEL_DIR}")
    print(f"Saved evaluation outputs to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
