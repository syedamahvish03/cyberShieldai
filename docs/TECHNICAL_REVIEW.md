# Technical Review and Next Steps

This review is based on the repository source available on the default branch at the time of review. It is a practical engineering checklist, not a penetration test or a guarantee that every deployment setting has been inspected.

## Strengths

- The application combines manual email/SMS text analysis with a separate Gmail monitoring workflow.
- Gmail OAuth uses a read-only scope for inbox monitoring.
- OAuth state is validated and connected Gmail refresh tokens are encrypted before database storage.
- The scheduled monitor endpoint is protected by a Bearer secret and only accepts POST requests.
- Gmail history checkpoints help avoid rescanning the entire mailbox on every run.
- The project has Django regression tests and GitHub Actions workflows.
- The repository includes model evaluation reports and confusion-matrix/ROC visualizations.

## High-priority improvements

### 1. Make model artifacts reproducible

The application imports four Joblib artifacts at module load, but the public repository excludes all `.pkl` files and the source datasets. A fresh clone therefore cannot reproduce the deployed inference environment. Add a trusted, documented artifact build/download process after confirming dataset and model redistribution rights. Never load model pickle files from untrusted sources.

### 2. Correct email evaluation leakage

The email training script currently fits TF-IDF on the complete dataset before splitting into training and test partitions. This leaks vocabulary information from the test partition. Use a scikit-learn Pipeline and split raw text before fitting. Recompute the classification report, confusion matrix, and ROC-AUC before presenting final benchmark claims.

### 3. Improve scheduled-monitor observability

GitHub Actions is configured for an approximately 15-minute schedule, but scheduled workflows can be delayed or disabled by platform inactivity policies. Add failure notifications or an external health check, and show the last successful scan time in the application. Keep the response payload small and avoid returning email content or credentials.

### 4. Review Google OAuth publishing status

If the OAuth consent screen remains in Testing mode, refresh tokens for external scopes can expire after a limited period. Confirm the consent-screen publishing status and verification requirements before describing the monitor as long-term unattended service.

### 5. Complete browser-extension integration

The current extension manifest grants host access only to localhost/127.0.0.1. It should be described as experimental/local-development functionality until it is configured for the deployed HTTPS API, tested end-to-end, and packaged for distribution.

### 6. Validate production settings

Before a public production launch, verify `DEBUG=False`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, HTTPS redirects, HSTS settings, database backups, secret rotation, and the actual Render environment. A source-code review cannot confirm secret values or live dashboard settings.

## Suggested order

1. Establish a repeatable, license-compliant model artifact process.
2. Fix and rerun the email model evaluation.
3. Add tests around Gmail OAuth, history pagination, duplicate handling, and alert delivery.
4. Add scheduler failure monitoring and a compact health/status view.
5. Finish and test the browser extension against the deployed API.
6. Reassess production hosting, OAuth verification, backups, and operational costs.

## Current honest project positioning

Describe CyberShield AI as a deployed, tested portfolio prototype for email/SMS phishing analysis and scheduled Gmail monitoring. Do not describe it as a fully audited enterprise email-security product, a guaranteed real-time service, or a system with independently verified 24/7 availability.
