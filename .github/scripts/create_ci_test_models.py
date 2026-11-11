"""Create temporary, synthetic ML artifacts for CI regression tests only.

The real trained models and datasets are intentionally excluded from Git.
These small models let Django's test suite import the analysis service without
adding or replacing production model artifacts.
"""
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "ml_model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TRAINING_TEXTS = [
    "Your account is suspended verify your password immediately",
    "Click this urgent link to claim your prize now",
    "Your bank details are required to avoid account closure",
    "Congratulations you won a free reward claim it today",
    "Please review the attached security alert and sign in",
    "The meeting is scheduled for tomorrow afternoon",
    "Thank you for your purchase your receipt is attached",
    "Can we discuss the project during our next meeting",
    "Your appointment is confirmed for Monday morning",
    "The team shared the updated report for your review",
]
LABELS = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]


def build_model(prefix):
    vectorizer = TfidfVectorizer()
    features = vectorizer.fit_transform(TRAINING_TEXTS)
    model = LogisticRegression(random_state=42)
    model.fit(features, LABELS)

    joblib.dump(model, MODEL_DIR / f"{prefix}_model.pkl")
    joblib.dump(vectorizer, MODEL_DIR / f"{prefix}_vectorizer.pkl")


if __name__ == "__main__":
    build_model("email")
    build_model("sms")
    print("Created temporary synthetic ML models for CI tests.")
