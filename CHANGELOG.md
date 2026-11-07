# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-07

### Breaking

- See repository diff for API changes in this release (secure defaults, renamed packages where applicable, context-aware constructors).

### Security

- Hardened defaults: TLS, timeouts, body limits, PII redaction where logging applies.

### Fixed

- Bug fixes from the v0.2.0 hardening pass.

### Changed

- CI uses go-version-file; added race, staticcheck, govulncheck, golangci-lint (gosec).



- Security: Stripe and Persona `VerifyWebhook` now verify HMAC-SHA256 signatures (`t=,v1=`) with constant-time comparison and a timestamp tolerance (default 5 minutes, `WebhookTolerance`).
- Security: Stripe, Persona, and Aliyun `VerifyWebhook` return `ErrWebhookUnverifiable` when the origin cannot be proven (no secret configured, or no signing scheme).

## [0.1.0]

- Initial release: unified `Provider` interface with Fake, Aliyun real-name, Stripe Identity, and Persona backends.
- HTTP clients injectable for httptest.
