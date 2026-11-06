import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
import pandas as pd
import re
import string
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# =========================
# LOAD DATASETS
# =========================

df1 = pd.read_csv("../datasets/sms/spam.csv", encoding='latin-1')

df2 = pd.read_csv("../datasets/manipulation/phishing_dataset_with_category.csv")

# =========================
# CLEAN SMS DATASET
# =========================

df1 = df1.rename(columns={
    "v1": "label",
    "v2": "message"
})

df1 = df1[["message", "label"]]

# =========================
# CLEAN PHISHING DATASET
# =========================

df2 = df2.rename(columns={
    "text": "message",
    "type": "label"
})

df2 = df2[["message", "label"]]

# =========================
# MERGE DATASETS
# =========================

df = pd.concat([df1, df2], ignore_index=True)

# Remove null rows

df.dropna(inplace=True)

# =========================
# NORMALIZE LABELS
# =========================

def normalize_label(label):

    label = str(label).lower()

    if label in ["spam", "phishing", "smishing", "1"]:
        return 1

    return 0

df["label"] = df["label"].apply(normalize_label)

# =========================
# CLEAN TEXT
# =========================

def clean_text(text):

    text = str(text).lower()

    # remove urls
    text = re.sub(r"http\S+", "", text)

    # remove numbers
    text = re.sub(r"\d+", "", text)

    # remove punctuation
    text = text.translate(
        str.maketrans("", "", string.punctuation)
    )

    text = text.strip()

    return text

df["message"] = df["message"].apply(clean_text)

# =========================
# FEATURES & LABELS
# =========================

X = df["message"]

y = df["label"]

# =========================
# TRAIN TEST SPLIT
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# =========================
# TF-IDF VECTORIZATION
# =========================

vectorizer = TfidfVectorizer(max_features=5000)

X_train_vec = vectorizer.fit_transform(X_train)

X_test_vec = vectorizer.transform(X_test)

# =========================
# MODEL TRAINING
# =========================

model = LogisticRegression()

model.fit(X_train_vec, y_train)

# =========================
# PREDICTIONS
# =========================

y_pred = model.predict(X_test_vec)

# =========================
# EVALUATION METRICS
# =========================

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

# =========================
# METRICS
# =========================

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

report = classification_report(y_test, y_pred)

print("\n===== SMS / CHAT MODEL =====\n")

print(f"Accuracy  : {accuracy * 100:.2f}%")

print(f"Precision : {precision * 100:.2f}%")

print(f"Recall    : {recall * 100:.2f}%")

print(f"F1 Score  : {f1 * 100:.2f}%")

print("\n===== CLASSIFICATION REPORT =====\n")

print(report)

# =========================
# SAVE METRICS
# =========================

with open("evaluations/sms/sms_metrics.txt", "w") as f:

    f.write("===== SMS / CHAT MODEL =====\n\n")

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

plt.title("SMS / Chat Confusion Matrix")

plt.savefig("evaluations/sms/sms_confusion_matrix.png")

plt.close()

# =========================
# ROC CURVE
# =========================

y_prob = model.predict_proba(X_test_vec)[:,1]

fpr, tpr, thresholds = roc_curve(y_test, y_prob)

roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6,5))

plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")

plt.plot([0,1], [0,1], linestyle='--')

plt.xlabel("False Positive Rate")

plt.ylabel("True Positive Rate")

plt.title("SMS / Chat ROC Curve")

plt.legend(loc="lower right")

plt.savefig("evaluations/sms/sms_roc_curve.png")

plt.close()

print("\n✅ Evaluation Files Saved")

# =========================
# SAVE MODEL
# =========================

joblib.dump(model, "sms_model.pkl")

joblib.dump(vectorizer, "sms_vectorizer.pkl")

print("\n✅ SMS / Chat Model Saved Successfully")