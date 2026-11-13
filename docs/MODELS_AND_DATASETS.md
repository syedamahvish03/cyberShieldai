# Models and Datasets

## Model files expected by the application

At startup, `backend/analyzer/services.py` loads these four files from the repository's `ml_model/` directory:

- `email_model.pkl`
- `email_vectorizer.pkl`
- `sms_model.pkl`
- `sms_vectorizer.pkl`

The `.gitignore` excludes `ml_model/*.pkl`, so trained artifacts are not committed to the public repository. A fresh clone must generate or receive these files through a trusted process before the complete prediction application can run.

**Do not commit private datasets, personal inbox data, OAuth credentials, or model artifacts unless you have confirmed that redistribution is permitted.** Only load Joblib/pickle files from a trusted source because deserializing an untrusted pickle can execute code.

## Dataset requirements

The training scripts expect these local CSV files:

| Model | Dataset path | Required columns / assumptions |
|---|---|---|
| Email | `datasets/emails/phishing_email.csv` | `text_combined`, `label`; labels must be 0 (safe) and 1 (phishing) |
| SMS | `datasets/sms/spam.csv` | Standard SMS Spam Collection columns `v1` and `v2` |
| SMS/chat | `datasets/manipulation/phishing_dataset_with_category.csv` | `text` and `type` |

The `datasets/` directory is ignored by Git. Obtain datasets from their original publishers, review their terms and licenses, and keep them locally. Do not add a dataset to this repository unless redistribution is explicitly allowed.

## Train the models

Run commands from the repository root after placing the datasets in the expected paths:

```bash
python -m pip install -r requirements.txt
python ml_model/email_train_model.py
python ml_model/sms_train_model.py
```

The scripts write the four model files into `ml_model/`. The email script also writes metrics, a confusion matrix, and an ROC curve under `evaluations/email/`; the SMS script writes corresponding outputs under `evaluations/sms/`.

The email training script uses a stratified train/test split and fits TF-IDF on the training partition only. The SMS script also fits its vectorizer on training data only. This prevents the test partition's vocabulary from influencing vectorizer fitting. The random split seed is fixed at 42 for repeatability with the same dataset and dependency versions.

## Reproducing results responsibly

1. Obtain the same dataset versions and confirm their licenses.
2. Record dataset source, version/date, and a SHA-256 checksum locally.
3. Install the dependencies from `requirements.txt`.
4. Run both training commands from the repository root.
5. Review the newly generated metrics and plots.
6. Compare results only when dataset versions, preprocessing, split strategy, and dependency versions match.

The metrics currently committed under `assets/` are historical outputs from earlier training runs. They are not automatically updated by the code changes in this repository. **Re-run training before quoting model accuracy, precision, recall, F1, or ROC-AUC as results from the corrected evaluation.** Do not treat historical metrics as proof of the corrected pipeline's performance.

## Important evaluation notes

- A single random hold-out split is useful for a project demonstration but does not establish performance on future or unseen real-world attacks.
- If near-duplicate messages or messages from the same campaign appear in both partitions, random splitting can still overestimate generalization. Consider group-based or time-based evaluation where dataset metadata permits.
- Accuracy alone can hide poor detection of the minority class. Report precision, recall, F1, confusion matrix, and ROC-AUC together.
- Model probability scores are not automatically calibrated confidence values.
- The email classifier is a text classifier; it does not establish sender authenticity or inspect attachments.
- The SMS script merges two sources and normalizes labels; review source label definitions before treating all non-spam categories as equivalent safe examples.

## Current reproducibility boundary

The training code is public, but source datasets and trained model artifacts are not included. This is intentional until their redistribution rights and privacy implications are confirmed. Therefore a recruiter can inspect the training logic, but cannot reproduce the exact deployed model from a Git clone alone without obtaining the permitted datasets and running the training scripts (or receiving artifacts through a trusted private channel).
