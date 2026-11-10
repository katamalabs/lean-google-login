# Lean Google Login

Free, no upsells, no telemetry. A **Sign in with Google** button for the WordPress
login screen, with an optional Google Workspace domain allow-list. A deliberately
minimal, secure sibling to [Lean SMTP](https://github.com/pjaudiomv/lean-smtp).

Password login is never disabled — the plugin only *adds* a button, so you can't be
locked out.

## What it does

- Adds a "Sign in with Google" button to `wp-login.php` using the OAuth2
  **authorization-code** flow (server-side; no client-side JavaScript, no bundled
  Google SDK).
- Restricts sign-in to one or more **Google Workspace domains** (optional). Matching
  is against the verified email domain and the Workspace `hd` claim.
- Signs in **existing users** by verified email. Creating accounts for new Google
  users is an explicit opt-in, with a role you choose.
- Links the Google account id (`sub`) to the WordPress user on first sign-in, so a
  later login to the same email must come from the same Google account.
- Encrypts the OAuth **client secret** at rest (AES-256, keyed to your site salts);
  it is never echoed back to the browser.
- Supports **wp-config.php overrides** for the client ID, secret, and allowed
  domains.

## Why only `openid email profile` (and why that matters)

Login needs only the **non-sensitive** `openid`, `email`, and `profile` scopes. Unlike
Google's restricted scopes, these require **no app verification** and work with an
External *or* Internal consent screen, Workspace or consumer. Because the identity
token is read straight from Google's TLS response during the code exchange, no JWT
signature verification is needed — one reason this ships only the redirect flow and
not One Tap.

## Setup

1. In the [Google Cloud Console](https://console.cloud.google.com/), create an OAuth
   2.0 Client ID of type **Web application**.
2. In **Settings → Lean Google Login**, copy the shown **Authorized redirect URI**
   into your OAuth client's redirect URIs (exact match).
3. Paste the **Client ID** and **Client Secret**, save.
4. Optionally set **Allowed domains** and the **new-user** behaviour.

## Development

```bash
make dev    # docker compose dev site at http://localhost:8083
make lint   # phpcs, WordPress-Core standard (tabs, snake_case)
make fmt    # phpcbf auto-fix
make test   # phpunit in Docker
make build  # git archive -> build/lean-google-login.zip
```

Run a single test: `docker compose -f docker-compose.test.yml run --rm test --filter test_name`.

## Security model

- The id_token is trusted **only** as read from the authorization-code exchange
  (Google's TLS response), never from the browser.
- CSRF is defended by a random `state` bound to the browser with a short-lived,
  HttpOnly, SameSite=Lax cookie and verified with `hash_equals`.
- A verified email (`email_verified`) is required; the domain allow-list is enforced
  on both sign-in and auto-creation.
- The Google `sub` is linked to the WordPress user to block email-reassignment
  account takeover.

## License

GPL-2.0-or-later.
