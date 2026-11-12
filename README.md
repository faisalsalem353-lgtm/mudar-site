# مُدار — مشروع الواجهة والخدمة الخلفية الموحّد

Target: existing GitHub `faisalsalem353-lgtm/mudar-site`, Vercel `mudar-site/mudartech`, domain `mudartech.com`.
This folder is an isolated candidate, not the deployed website. It contains no customer data or secrets and has not been pushed to `main`.

## Implemented
- Arabic RTL landing, independent registration/login/logout, session-based private account page, existing brand and palette.
- scrypt password hashes; opaque expiring verification/recovery/link tokens stored as SHA-256 digests. CSRF and exact-origin validation; session invalidation after recovery; database-backed rate limits.
- SMTP verification and password recovery adapters, disabled honestly until configured. Production registration requires SMTP; production login requires email verification. Development accounts are deliberately unverified and must not be migrated to production.
- Stable UUID account ID, one Telegram ID per account and one account per Telegram ID. Separate authenticated bot endpoint; payload prefix `m_` avoids confusing legacy activation tokens. Link issuance disabled until reviewed bot handler integration is installed and `MUDAR_BRIDGE_ENABLED=1`.
- PostgreSQL adapter for production and explicit local SQLite for disposable development only. No legacy DB imports, automatic migrations, payments, CV sharing or real email/application sending were executed.

## Local development
Use environment variables (not command-line secret values) for `MUDAR_SESSION_SECRET` (random, >=32 characters), `MUDAR_LOCAL_DB` (explicit temporary/local file) and `MUDAR_PUBLIC_ORIGIN=http://127.0.0.1:5180`. Install requirements in an isolated environment. Run `python manage.py init-local`, then `python app.py`. No fallback session secret is embedded.

Tests: `python -m unittest discover -s tests -v`.

## Cloud activation prerequisites
1. Create or select an approved NEW cloud PostgreSQL database, distinct from `medar` and `medar_next`; obtain permission separately before initializing any cloud schema. Adapter SQL is prepared but has not been integration-tested against PostgreSQL in this session.
2. Set runtime environment values in Vercel: session secret, public HTTPS origin, PostgreSQL connection URL with provider-required TLS; SMTP host/port/user/password/from on an authenticated provider. Never paste secret values in chat, commit them, or use a public frontend environment prefix.
3. Review the explicit schema in `store.py`; only then initialize the new approved database using `manage.py init-cloud --approved-new-database`. Vercel imports do not create tables.
4. Configure Flask/Python framework recognition in Vercel; see https://vercel.com/docs/frameworks/backend/flask . No root index.html is included here to shadow the server. CDN assets must live under public; use public/app.css and public/app.js with URLs /assets/... as below.
5. Assets use the same public/assets paths in Flask and the Vercel CDN; no separate frontend host is required.
6. Deploy a PREVIEW branch, not main. Test real SMTP verification/recovery on an owner-controlled test mailbox, PostgreSQL concurrency and uniqueness, HTTPS cookies, origin validation, logout, private account isolation and the bot callback on test accounts.
7. Integrate `bot_bridge.link_mudar_account` into /start BEFORE the legacy token handler only for `m_` payloads. Pass Telegram's actual update.effective_user.id. Never use a browser-provided Telegram ID. Do not reuse paid activation codes: identity linking grants no paid entitlement. Existing bot profile access must be adapted to the shared UUID before claiming full data unification.
8. Cloud identity link, legacy migration, paid subscriptions, profile/CV persistence and production promotion are NOT completed by this candidate. Customer mapping requires explicit review; never auto-merge accounts by matching email/name.

## Scope limits
- No policy/terms acceptance flow, account deletion, production backup, paid subscription, CV storage or migrated legacy profile has been added in this initial account foundation.
- No connection to the current production database or running Telegram bot.
- Mailer is covered by an injected in-memory test callback only; no real SMTP send has been performed.
- Development server uses disposable test data and must never be exposed as production.
- Exact-origin requirement: choose a single canonical host (mudartech.com); redirect www consistently before auth. Fix PUBLIC_ORIGIN for each preview host; avoid wildcard origins.
- Before launch: set a provider retention/backup policy; rate-limit at the edge as well as the DB; confirm session expiration and SMTP delivery; review against production abuse and email enumeration; collect appropriate privacy/terms consent.
