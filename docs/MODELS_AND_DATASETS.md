# Models and Datasets

## Model files expected by the application

At startup, `backend/analyzer/services.py` loads these files from the repository's `ml_model/` directory:

- `email_model.pkl`
- `email_vectorizer.pkl`
- `sms_model.pkl`
- `sms_vectorizer.pkl`

The `.gitignore` excludes `ml_model/*.pkl`, so these files are not present in the public repository tree. They must be generated locally or supplied through a separate trusted artifact process before the full app can run from a fresh clone.

Only load Joblib/pickle model files from a trusted source. Deserializing an untrusted pickle file can execute arbitrary code.

## Training data expected by the scripts

The training scripts currently expect local CSV files:

- Email training: `datasets/emails/phishing_email.csv`, with `text_combined` and `label` columns.
- SMS/chat training: `datasets/sms/spam.csv` and `datasets/manipulation/phishing_dataset_with_category.csv`, with the columns used in the scripts.

The `datasets/` directory is ignored by Git. Verify dataset licenses and redistribution permissions before publishing or sharing any data.

## Training scripts

The scripts are:

- `ml_model/email_train_model.py`
- `ml_model/sms_train_model.py`

They use TF-IDF and Logistic Regression and save Joblib model/vectorizer files. Review the relative paths in the scripts and run them from the working directory expected by their dataset paths; the scripts currently use relative paths and do not create all output directories automatically.

## Evaluation caution

The current email training script calls `fit_transform` on the complete email text column before the train/test split. This means the vectorizer learns vocabulary from both partitions. For a more rigorous benchmark, split raw text first and fit the vectorizer only on the training partition, ideally by using a scikit-learn `Pipeline` and cross-validation. Recompute the metrics before using them as a final independent performance claim.

The checked-in `assets/*_metrics.txt` files are historical reports. They are useful as project evidence but cannot be independently regenerated from this repository alone because the source datasets and model artifacts are not included.
