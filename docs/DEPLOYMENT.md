# Deployment Guide

This guide documents the environment configuration used by the current Django application. Keep all real values in Render environment settings or another secret manager; never commit them.

## Render service

The repository's production start script is `backend/start.sh`. It changes into the backend directory, runs database migrations, and starts Gunicorn on the port supplied by the hosting platform.

Typical Render configuration:

- **Root directory:** repository root (unless the service is configured otherwise)
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `bash backend/start.sh`

The deployed service also needs the trained model artifacts at `ml_model/email_model.pkl`, `ml_model/email_vectorizer.pkl`, `ml_model/sms_model.pkl`, and `ml_model/sms_vectorizer.pkl`. Those files are excluded from this repository. The current deployment must therefore provide them through a separately managed, license-cleared artifact/build process. Do not assume the public GitHub repository alone is sufficient to recreate the live deployment.

## Environment variables

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Django signing and session secret; use a strong unique value |
| `DEBUG` | Set to `False` in production |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated trusted HTTPS origins |
| `SECURE_SSL_REDIRECT` | Enable HTTPS redirect when the proxy configuration supports it |
| `SECURE_HSTS_SECONDS` | HSTS duration; enable only after HTTPS is verified |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | Optional HSTS subdomain setting |
| `SECURE_HSTS_PRELOAD` | Optional HSTS preload setting |
| `DATABASE_URL` | Optional PostgreSQL connection URL; SQLite is used when absent |
| `GOOGLE_OAUTH_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_OAUTH_REFRESH_TOKEN` | Refresh token for the dedicated Gmail API sender account |
| `GOOGLE_OAUTH_SENDER_EMAIL` | Sender address associated with the sender OAuth credentials |
| `GMAIL_TOKEN_ENCRYPTION_KEY` | Fernet key used to encrypt connected users' Gmail refresh tokens |
| `GMAIL_MONITOR_SECRET` | Shared secret required by the internal scheduled monitor endpoint |

The sample `.env.example` lists these variables. Do not put real values in documentation, screenshots, GitHub Actions logs, or chat messages.

## Gmail sender versus monitored inbox

These are separate integrations:

1. **Notification sender:** `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_REFRESH_TOKEN`, and `GOOGLE_OAUTH_SENDER_EMAIL` authorize the Gmail API backend to send verification and warning messages.
2. **Monitored inbox:** a signed-in CyberShield user connects their own Gmail account through the application's OAuth flow. The resulting refresh token is encrypted and stored per user.

Changing the notification sender requires authorizing the new sender account and updating the sender OAuth configuration together. Changing the sender email string alone is insufficient.

## GitHub Actions scheduler

The workflow at `.github/workflows/gmail-monitor.yml` runs at minutes 7, 22, 37, and 52 of each hour (approximately every 15 minutes). It can also be started manually from GitHub Actions.

Configure these GitHub repository Actions secrets:

- `GMAIL_MONITOR_URL`: the full HTTPS URL ending in `/internal/gmail/monitor/`.
- `GMAIL_MONITOR_SECRET`: the same raw secret value configured as Render's `GMAIL_MONITOR_SECRET`. The workflow adds the `Bearer ` prefix in the Authorization header.

The Django endpoint accepts POST and checks the header in the form `Authorization: Bearer <secret>`. Do not put the secret directly in the workflow YAML.

GitHub scheduled workflows are best-effort: execution can be delayed, and the scheduler should not be described as a guaranteed real-time service. Monitor the Actions run history for failures.

## Verification after deployment

1. Confirm the Render service starts and migrations complete.
2. Open the application and verify registration/login and dashboard behavior.
3. Connect a test Gmail mailbox using the Google OAuth flow.
4. Run the Gmail monitor workflow manually from GitHub Actions.
5. Inspect the workflow log for a JSON result with `status: completed` and `errors: 0`.
6. Confirm the dashboard records the expected new-message result.
7. Test alert delivery with a controlled test message and verify the dedicated sender configuration.
8. Never use an actual phishing link or send real sensitive messages for testing.

## OAuth availability

Google OAuth consent-screen settings affect refresh-token lifetime. If the OAuth app remains in Testing mode, refresh tokens for external scopes can expire after a limited period (commonly seven days). Review the current Google Cloud OAuth publishing status and applicable verification requirements before promising long-term unattended monitoring.
