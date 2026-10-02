# Personal integration track

Baseline: upstream stable `v0.36.2`, commit `dd61ac3c84d6b238108dc8438b53043b5177a662`.
The fork's `main` tracks upstream; personal work targets `personal`. Do not deploy a nightly/main
build against production data. See upstream `CONTRIBUTING.md` for the migration warning.

## Boundary and current scope

Rauthy owns authentication, sessions, and OIDC issuance. Platform keeps its business accounts,
entitlements, and wallets. Asset, Loom, and Hook integrations stay in their own repositories.
This is a clean new integration: legacy account mapping and data migration are out of scope.
Existing databases must not be deleted or changed by these test tools.

The first slice adds an isolated synthetic OAuth provider. It changes no Rauthy runtime code,
database schema, production configuration, credentials, or deployment. Revert the slice to remove
it. Passing its tests proves the fixture transport works; it does not prove Rauthy integration.

## Source-verified compatibility limits

Read `AuthProviderCallback::extract_user` and `AuthProviderIdClaims::validate_update_user` in
`src/data/src/entity/auth_providers.rs` at the baseline above:

- A plain OAuth response can contain only an access token; Rauthy then fetches userinfo
- Upstream `sub`, `id`, or `uid` may be a JSON string or number
- Missing/null email is rejected before account lookup; do not synthesize an email to bypass it
- Missing `email_verified` becomes false for a new federated account; do not invent verification
- Only `preferred_username` or `login` populate the preferred username; `username` is not mapped
- Keep `auto_link=false`; matching email alone must not silently link independent identities

Those are source observations, not completed Rauthy HTTP tests. Numeric IDs and an upstream
`username` field alone do not make Linux.do a drop-in provider. If Linux.do cannot supply a usable
email, leave that login method disabled until an explicit onboarding design resolves the gap.
Standard Rauthy-managed test accounts can establish the new OIDC integration independently.

## Small-step implementation and acceptance gates

1. Run the fixture tests below; use only synthetic data and isolated services
2. Add an opt-in Rauthy OIDC login in Platform, with configuration absent/off by default. Verify
   discovery, exact issuer/audience, signature, state, nonce, PKCE, and registered callbacks
3. Create a fresh Platform business account using verified `(issuer, subject)` identity. Email and
   display name remain attributes, not identity keys. No legacy mapping or email-based linking
4. Test repeat/concurrent first logins, rejected issuer/audience/signature, expired/replayed codes,
   missing optional claims, logout, disabled accounts, and fresh account creation without secrets
5. Check Asset's existing issuer/audience/JWKS verification. Configure Rauthy RS256 where required;
   do not relax verification to accommodate a default algorithm. Test the Account session contract
   (`principal`, `access_token`, `expires_at`) separately from an OIDC token
6. Preserve Loom's system-browser S256 flow and device possession/nonce/revocation checks while
   changing its login integration. Hook integration requires its own repository-level tests
7. Before any real rollout, require isolated end-to-end tests, explicit deployment authorization,
   and a documented off switch. This repository slice neither deploys nor creates real accounts

## Synthetic OAuth provider

Python 3.10+ standard library only. From the repository root:

```sh
python3 -m unittest discover -s personal/tests/oauth_provider -v
python3 personal/tests/oauth_provider/stub.py --scenario numeric_no_email
```

The stub binds only `127.0.0.1:19090`. `--port 0` requests an ephemeral port. It prints a disabled
Rauthy custom-provider configuration with actual endpoint URLs and `auto_link=false`. The stub is
an OAuth fixture, not OIDC: no discovery/JWKS, ID tokens, real login, or real provider credentials.
It accepts the public client `synthetic-rauthy-client` with S256 PKCE; it does not model Linux.do's
actual client authentication or network service. Codes expire after 60 seconds and tokens after
300; codes are single-use. Requests, codes, tokens, and claims are not logged.

For a later isolated Rauthy test, set the callback to the exact local Rauthy UI callback using
`--callback http://127.0.0.1:PORT/auth/v1/providers/callback`. Use Rauthy's documented local HTTP
dev setup and a fresh disposable database. Only there, explicitly enable the emitted provider.
Run each scenario against the actual Rauthy flow and inspect outcomes without logging tokens.
Missing/null email must fail cleanly; unverified/absent verification must never become true;
same-email different identities must not auto-link. The fixture suite alone does not test these
Rauthy outcomes, business-account creation, cryptographic token validation, or browser behavior.
