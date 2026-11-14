=== Lean Sign in with Google ===
Contributors: pjaudiomv
Tags: login, google, oauth, google-workspace, sso
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A minimal, secure "Sign in with Google" button for WordPress, with an optional Google Workspace domain allow-list. No upsells, no telemetry.

== Description ==

Lean Sign in with Google adds a **Sign in with Google** button to your WordPress login screen using the standard OAuth2 authorization-code flow. It is deliberately small: one button, a handful of settings, and no bundled Google SDK.

**Everything is free.** There is no pro version, no paid add-ons, no account to create, and no upsell banners in the admin. Nothing phones home — the plugin makes no network requests other than the Google OAuth calls needed to sign a person in.

* **Workspace domain limiting**: restrict sign-in to one or more Google Workspace domains, enforced on the Workspace `hd` claim — the membership signal Google documents — not on the email domain alone. An account whose `hd` isn't in your list is turned away. Leave it blank to allow any verified Google account.
* **Existing users by default**: people who already have a WordPress account sign in by matching their verified Google email. A pre-existing account is auto-linked to a first sign-in only when Google is authoritative for the address (a Workspace or Gmail account). Creating accounts for new Google users is an explicit opt-in, with a role you choose.
* **Account-takeover protection**: the Google account id (`sub`) is the primary key for an established link, so a returning user is matched by `sub` first and a later login to the same email must come from the same Google account.
* **Honors your login policies**: core account eligibility (multisite spam/deleted and site membership) and the `wp_authenticate_user` policy filter that account-disable and 2FA plugins hook are enforced before a session is issued.
* **Password login stays enabled**: the plugin only *adds* a button. Your normal username/password login keeps working, so there is no way to lock yourself out.
* **Encrypted secret**: the OAuth client secret is AES-256 encrypted at rest, keyed to your site salts, and never echoed back to the browser.
* **wp-config.php overrides**: pin the client ID, secret, or allowed domains in code instead of the database, so credentials can live in environment variables and never diverge between environments.

**Why no One Tap, and why Workspace-friendly without Google verification:** this plugin uses only the non-sensitive `openid`, `email`, and `profile` scopes and the server-side redirect flow. That means no Google app-verification process, no client-side JavaScript, and no JWT signature gymnastics — the identity token is read straight from Google's own TLS response during the code exchange. It works with an External or Internal OAuth consent screen, for Workspace or consumer Google accounts (restrict to your domain to keep it Workspace-only).

Consumer-Gmail One Tap and Microsoft 365 login are deliberate non-goals — they would add client-side token verification and more moving parts than the rest of the plugin combined.

== Installation ==

1. Upload the plugin and activate it.
2. In the [Google Cloud Console](https://console.cloud.google.com/), create an OAuth 2.0 Client ID of type **Web application** (set the OAuth consent screen to Internal for a Workspace org, or External for consumer accounts).
3. Go to Settings → Lean Sign in with Google and copy the **Authorized redirect URI** shown there into your OAuth client's "Authorized redirect URIs" in Google Cloud (it must match exactly).
4. Paste the **Client ID** and **Client Secret** into the plugin and save.
5. Optionally set one or more **Allowed domains**, and decide whether new Google users should get an account.
6. A "Sign in with Google" button now appears on your login screen.

== Frequently Asked Questions ==

= Does this disable password login? =

No. It only adds a button. Your normal WordPress login keeps working, so you can never be locked out.

= Can I restrict sign-in to my company's Google Workspace domain? =

Yes. Enter your domain(s) under Allowed domains. Only accounts whose verified email or Workspace hosted-domain claim match are allowed in.

= Does it work with consumer @gmail.com accounts? =

Yes, if you leave the domain allow-list blank. To keep it Workspace-only, set your Workspace domain in Allowed domains.

= Does it need a Google app verification or security assessment? =

No. It uses only the non-sensitive openid / email / profile scopes, which need no verification.

= Is it really free? Is there a pro version? =

Yes, free. There is no pro version and no upsells.

== Screenshots ==

1. Settings → Lean Sign in with Google: paste your Google OAuth client ID and secret, copy the redirect URI into Google Cloud, limit sign-in to one or more Workspace domains, and choose whether new users are created and with which role.
2. The "Sign in with Google" button on the WordPress login screen. Normal password login stays enabled alongside it.

== External services ==

This plugin connects to Google's OAuth 2.0 and OpenID Connect services to authenticate people who choose to sign in with Google. This connection is what makes the "Sign in with Google" button work; the plugin does not function without it, and it contacts no other external service.

The connection happens only when a site administrator has configured a Google OAuth client and a visitor clicks the "Sign in with Google" button. It involves these Google endpoints:

* `https://accounts.google.com/o/oauth2/v2/auth` — the visitor's browser is redirected here to sign in to Google and consent. The plugin sends your configured OAuth client ID, the requested scopes (`openid`, `email`, `profile`), the redirect URI back to your site, and an anti-CSRF `state` value.
* `https://oauth2.googleapis.com/token` — after the visitor returns, your server exchanges the one-time authorization code for an identity token. The plugin sends your OAuth client ID, client secret, the authorization code, and the redirect URI. In response, Google returns the signed-in person's Google account identifier, email address, email-verified flag, and (if present) name and Workspace hosted-domain claim, which the plugin uses to match or create the WordPress account.

No data is sent to Google unless and until a visitor initiates a Google sign-in. The plugin sends no analytics, telemetry, or personal data of its own to any service.

This service is provided by Google. By using it you are subject to:

* Google Terms of Service: https://policies.google.com/terms
* Google Privacy Policy: https://policies.google.com/privacy
* Google API Services User Data Policy: https://developers.google.com/terms/api-services-user-data-policy

== Changelog ==

= 0.1.0 =

* Initial release: "Sign in with Google" button on wp-login.php via the OAuth2 authorization-code flow, optional Workspace domain allow-list.

== Upgrade Notice ==

= 0.1.0 =

First release.
