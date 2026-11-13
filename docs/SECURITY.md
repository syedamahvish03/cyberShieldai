# Security Notes

This document describes the security controls visible in the current CyberShield AI source code and the precautions required when deploying it. It is not a security certification or a penetration-test report.

## Implemented controls

- Gmail OAuth requests the Gmail read-only scope for inbox monitoring.
- OAuth state is generated per connection attempt and checked in the callback.
- Gmail refresh tokens are encrypted with Fernet before being stored in the database.
- The scheduled Gmail monitor endpoint requires a constant-time comparison against an expected Bearer token and accepts POST only.
- The Gmail monitor excludes attachments from analysis.
- Email body text is used in memory for classification; the saved Gmail history contains limited message metadata and detection fields.
- Gmail-monitor history older than 30 days is purged by the monitoring task.
- The Gmail API sender backend reads credentials from Django settings populated by environment variables; credentials are not intended to be stored in source control.

## Deployment checklist

- [ ] Set a strong, unique `SECRET_KEY`; never reuse a development key.
- [ ] Set `DEBUG=False`.
- [ ] Set `ALLOWED_HOSTS` to the exact deployed hostnames.
- [ ] Set `CSRF_TRUSTED_ORIGINS` to the exact HTTPS origins used by the site.
- [ ] Enable HTTPS and secure cookies.
- [ ] Keep OAuth client secret, refresh token, Fernet key, database URL, and monitor secret in the hosting provider's secret/environment-variable settings.
- [ ] Use a dedicated sender Gmail account and grant only the scopes required by the app.
- [ ] Keep Google OAuth consent-screen publishing/testing status in mind; testing-mode refresh tokens can expire.
- [ ] Rotate any credential that has ever been committed, pasted into chat, or exposed in logs.
- [ ] Review Google Cloud OAuth test users and revoke access when an account should no longer be connected.
- [ ] Avoid using real personal inbox data in screenshots or public test examples.

## Data handling

The monitor fetches message metadata and text for analysis. Attachments are deliberately skipped. The implementation stores a limited history record rather than the complete message body; the code also stores the sender, subject, received date, URL hostnames, prediction, probability, and related detection details. Gmail-source history is configured for 30-day retention.

This does not mean no data is processed: message text is transmitted from Gmail to the application process over the Gmail API and analyzed in memory. Users should connect only mailboxes they are authorized to access.

## Important limitations

- The monitor endpoint is a powerful internal action. Treat `GMAIL_MONITOR_SECRET` as a credential and never expose it in client-side code.
- The current code uses a shared Bearer secret for the scheduler endpoint; it is not a full per-service identity system.
- Security settings must be reviewed against the actual Render environment before production use.
- The application has not been represented as independently audited or penetration-tested.
