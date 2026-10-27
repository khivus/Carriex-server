# Changelog

**English** | [Русский](docs/CHANGELOG.ru.md)

All notable changes are recorded here. Versions follow Semantic Versioning.

## [Unreleased]

### Added
- `/health` advertises server version, protocol and an explicit supported app-code range for simple full/limited/incompatible client guidance.

- `.env.example` lists setting ranges, units, defaults, path rules, and validation
  commands, including the 1-365-day statistics retention limit. A version header,
  numbered category dividers, category descriptions and one-line setting notes
  make the plain-text template easier to scan.
- English/Russian language controls for pairing and local statistics pages.
- Russian README and documentation companions with English comparison tools.
- Documentation lives in `docs/`; the English README and changelog remain at the
  repository root with Russian-version links at the top. Source archives include
  the moved documents and referenced deployment files.

### Fixed
- CI installs the Linux server dependencies needed by real TLS listener tests.
- Docker CI verifies the configured paired HTTPS server and authenticated WSS,
  including address changes and preserved identity, instead of the legacy HTTP flow.

## [0.5.0] - 2026-10-22

### Added
- Permanent group admins can publish signed group-name changes visible to current
  members. Renames preserve membership and sender-key epochs; invitations issued
  before a rename still join through the existing admission-checkpoint flow.
- Optional direct-message read reports at `POST /messages/<own-id>/read`, separate
  from recipient delivery acknowledgements. Authenticated recipients can report
  already delivered messages; status polling and WebSocket receipts expose `read`.
  Reports persist through restart, are idempotent, and do not reveal quarantined
  or hidden-delivery messages. Android read reporting is disabled by default.
- Android drawer/settings reorganization, opt-in request auto-accept, shared
  message/group request review, independent invitation alerts, and theme/accent
  preferences.

## [0.4.0] - 2026-10-20

### Added
- Admin-managed groups with signed membership transitions, accepted invitations,
  permanent admin ownership, sender-key distribution and encrypted fan-out.
  Every join, removal and leave advances the membership epoch and requires
  every current sender to rotate its keys before sending again. See [group protocol](docs/GROUPS.md).
- Count-only notification GET with persistent, revocable credentials restricted
  to the owner's counts; indexed queue counts and arrival revisions.
- Optional persistent hourly relay statistics, a localhost dashboard, and JSON/CSV
  export for practical experiments (`CARRIEX_STATISTICS=1`).

### Fixed
- Group event history is authorized per membership period. New members and
  invitees cannot download earlier activity, and rejoining does not reveal an
  absence. Admin-signed join checkpoints replace full-history bootstrapping.
- Oversized messages return HTTP 413, distinct from temporary capacity limits.
- Paired `.env` parsing accepts the documented queue TTL setting.

## [0.1.0] - 2026-09-07

### Added
- HTTP message submission, queue retrieval, and health endpoints.
- WebSocket delivery and offline in-memory queues.
- Real-socket integration tests.
- Python packaging, a shared package/API version, and documentation.
- Docker and Compose deployment with a non-root Gunicorn server.
- GitHub CI, dependency updates, and contribution templates.
