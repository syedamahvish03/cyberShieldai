import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# Load dataset
df = pd.read_csv("../datasets/emails/phishing_email.csv")

# Features and labels
X = df['text_combined']
y = df['label']

# Convert text into numerical vectors
vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = LogisticRegression()

model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

# Save model and vectorizer
joblib.dump(model, "email_model.pkl")
joblib.dump(vectorizer, "email_vectorizer.pkl")

# =========================
# METRICS
# =========================

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

report = classification_report(y_test, y_pred)

print("\n===== EMAIL MODEL =====\n")

print(f"Accuracy  : {accuracy * 100:.2f}%")

print(f"Precision : {precision * 100:.2f}%")

print(f"Recall    : {recall * 100:.2f}%")

print(f"F1 Score  : {f1 * 100:.2f}%")

print("\n===== CLASSIFICATION REPORT =====\n")

print(report)

# =========================
# SAVE METRICS
# =========================

with open("evaluations/email/email_metrics.txt", "w") as f:

    f.write("===== EMAIL MODEL =====\n\n")

    f.write(f"Accuracy  : {accuracy * 100:.2f}%\n")

    f.write(f"Precision : {precision * 100:.2f}%\n")

    f.write(f"Recall    : {recall * 100:.2f}%\n")

    f.write(f"F1 Score  : {f1 * 100:.2f}%\n\n")

    f.write("===== CLASSIFICATION REPORT =====\n\n")

    f.write(report)

# =========================
# CONFUSION MATRIX
# =========================

cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(6,5))

sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=['Safe', 'Phishing'],
    yticklabels=['Safe', 'Phishing']
)

plt.xlabel("Predicted")

plt.ylabel("Actual")

plt.title("Email Confusion Matrix")

plt.savefig("evaluations/email/email_confusion_matrix.png")

plt.close()

# =========================
# ROC CURVE
# =========================

y_prob = model.predict_proba(X_test)[:,1]

fpr, tpr, thresholds = roc_curve(y_test, y_prob)

roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6,5))

plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")

plt.plot([0,1], [0,1], linestyle='--')

plt.xlabel("False Positive Rate")

plt.ylabel("True Positive Rate")

plt.title("Email ROC Curve")

plt.legend(loc="lower right")

plt.savefig("evaluations/email/email_roc_curve.png")

plt.close()

print("\n✅ Evaluation Files Saved")