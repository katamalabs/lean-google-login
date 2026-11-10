<?php
/**
 * The login flow: the "Sign in with Google" button, the two admin-post
 * endpoints that drive the OAuth round-trip, and the mapping from a Google
 * identity to a WordPress user.
 *
 * The flow is anonymous (it starts from wp-login.php, before anyone is signed
 * in), so CSRF is defended not by a WordPress nonce — which is bound to a
 * logged-in session — but by a random `state` echoed through Google and bound
 * to the browser with a short-lived, HttpOnly, SameSite=Lax cookie, verified
 * with hash_equals on return. A matching server-side transient carries the
 * post-login redirect target and enforces one-time use and expiry.
 *
 * The identity-to-user step, authenticate_claims(), is pure of HTTP and cookies
 * so it can be unit-tested directly: it gates on a verified email, a non-empty
 * stable `sub`, and the optional Workspace (`hd`) allow-list; resolves the user
 * by that `sub` first (falling back to email only to auto-link a pre-existing
 * account when Google is authoritative for the address); enforces core account
 * eligibility before a session is issued; and optionally provisions a new user
 * when auto-create is enabled.
 *
 * This plugin never disables password login — it only adds a button — so there
 * is no way to lock an administrator out of their own site.
 *
 * @package lean-google-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Lean_Google_Login_Auth {

	const OPTION_ALLOWED_DOMAINS = 'lean_google_login_allowed_domains';
	const OPTION_AUTO_CREATE     = 'lean_google_login_auto_create';
	const OPTION_DEFAULT_ROLE    = 'lean_google_login_default_role';

	// The Google `sub` (stable account id) linked to a WP user, so a later login
	// to the same email must come from the same Google account.
	const META_SUB = 'lean_google_login_sub';

	// admin-post action that begins the flow (priv + nopriv). The callback action
	// lives on the client class, since it is also the registered redirect URI.
	const START_ACTION = 'lean_google_login_start';

	const TRANSIENT_PREFIX = 'lgl_state_';
	const STATE_TTL        = 600;

	public static function init(): void {
		add_action( 'admin_post_nopriv_' . self::START_ACTION, [ static::class, 'handle_start' ] );
		add_action( 'admin_post_' . self::START_ACTION, [ static::class, 'handle_start' ] );
		add_action( 'admin_post_nopriv_' . Lean_Google_Login_Client::CALLBACK_ACTION, [ static::class, 'handle_callback' ] );
		add_action( 'admin_post_' . Lean_Google_Login_Client::CALLBACK_ACTION, [ static::class, 'handle_callback' ] );

		add_action( 'login_form', [ static::class, 'render_button' ] );
		add_action( 'login_enqueue_scripts', [ static::class, 'enqueue_button_css' ] );
		add_filter( 'login_message', [ static::class, 'login_error_message' ] );
	}

	// -------------------------------------------------------------------------
	// Endpoints
	// -------------------------------------------------------------------------

	/**
	 * Begin the flow: mint a state, bind it to the browser with a cookie, stash
	 * the redirect target server-side, and send the browser to Google's consent
	 * screen.
	 */
	public static function handle_start(): void {
		if ( ! Lean_Google_Login_Client::is_configured() ) {
			self::redirect_to_login( 'config', __( 'Google sign-in is not configured yet.', 'lean-google-login' ) );
		}

		$state       = bin2hex( random_bytes( 32 ) );
		$redirect_to = self::requested_redirect_to();

		set_transient(
			self::TRANSIENT_PREFIX . hash( 'sha256', $state ),
			[ 'redirect_to' => $redirect_to ],
			self::STATE_TTL
		);
		self::set_state_cookie( $state );

		// A single configured domain is passed as Google's `hd` hint so the
		// account chooser is pre-filtered; it is not relied on for enforcement.
		$domains = self::allowed_domains();
		$hd      = 1 === count( $domains ) ? $domains[0] : '';

		nocache_headers();
		// Deliberately wp_redirect, not wp_safe_redirect: the target is Google's
		// consent screen, an external host wp_safe_redirect would reject.
		wp_redirect( Lean_Google_Login_Client::authorize_url( Lean_Google_Login_Client::redirect_uri(), $state, $hd ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- External OAuth consent URL.
		exit;
	}

	/**
	 * Google's redirect target: verify the state cookie, exchange the code,
	 * resolve the WordPress user, set the auth cookie, and send them on.
	 */
	public static function handle_callback(): void {
		$cookie = self::read_state_cookie();
		$state  = self::get_param( 'state' );
		self::clear_state_cookie();

		if ( '' === $cookie || '' === $state || ! hash_equals( $cookie, $state ) ) {
			self::redirect_to_login( 'state', __( 'The sign-in request could not be verified. Please try again.', 'lean-google-login' ) );
		}

		$key  = self::TRANSIENT_PREFIX . hash( 'sha256', $state );
		$data = get_transient( $key );
		delete_transient( $key );
		if ( ! is_array( $data ) ) {
			self::redirect_to_login( 'state', __( 'The sign-in request expired. Please try again.', 'lean-google-login' ) );
		}
		$redirect_to = isset( $data['redirect_to'] ) ? (string) $data['redirect_to'] : '';

		$error = self::get_param( 'error' );
		if ( '' !== $error ) {
			self::redirect_to_login( 'google', $error );
		}

		$code = self::get_param( 'code' );
		if ( '' === $code ) {
			self::redirect_to_login( 'google', __( 'Google returned no authorization code.', 'lean-google-login' ) );
		}

		$claims = Lean_Google_Login_Client::exchange_code( $code, Lean_Google_Login_Client::redirect_uri() );
		if ( is_wp_error( $claims ) ) {
			self::redirect_to_login( 'google', $claims->get_error_message() );
		}

		$user = self::authenticate_claims( $claims );
		if ( is_wp_error( $user ) ) {
			self::redirect_to_login( 'denied', $user->get_error_message() );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
		do_action( 'wp_login', $user->user_login, $user );

		$dest = '' !== $redirect_to ? $redirect_to : admin_url();
		/** This filter is documented in wp-login.php */
		$dest = apply_filters( 'login_redirect', $dest, $redirect_to, $user );
		wp_safe_redirect( $dest );
		exit;
	}

	// -------------------------------------------------------------------------
	// Identity → WordPress user (pure of HTTP / cookies; unit-tested)
	// -------------------------------------------------------------------------

	/**
	 * Resolve a verified Google identity to a WordPress user, creating one if
	 * auto-provisioning is on and no match exists.
	 *
	 * @param array<string, mixed> $claims The id_token claims from the exchange.
	 * @return WP_User|WP_Error
	 */
	public static function authenticate_claims( array $claims ) {
		$email = isset( $claims['email'] ) ? sanitize_email( (string) $claims['email'] ) : '';
		if ( '' === $email ) {
			return new WP_Error( 'lean_google_login_no_email', __( 'Google did not return an email address.', 'lean-google-login' ) );
		}

		if ( ! self::claim_is_true( $claims['email_verified'] ?? false ) ) {
			return new WP_Error( 'lean_google_login_unverified', __( 'Google has not verified this email address, so it cannot be used to sign in.', 'lean-google-login' ) );
		}

		// The stable Google account id. It is the primary key for an established
		// link, so a login with no `sub` can neither be matched nor bound.
		$sub = isset( $claims['sub'] ) ? trim( (string) $claims['sub'] ) : '';
		if ( '' === $sub ) {
			return new WP_Error( 'lean_google_login_no_sub', __( 'Google did not return an account identifier.', 'lean-google-login' ) );
		}

		if ( ! self::domain_allowed( $claims, $email ) ) {
			return new WP_Error( 'lean_google_login_domain', __( 'This email domain is not permitted to sign in here.', 'lean-google-login' ) );
		}

		$user = self::resolve_user( $claims, $email, $sub );
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		// Enforce core account eligibility (multisite spam/deleted and site
		// membership, plus the post-password policy filter that account-disable
		// and 2FA plugins hook) before any session is issued. The password
		// handlers are deliberately not replayed — see enforce_account_eligibility.
		$eligible = self::enforce_account_eligibility( $user );
		if ( is_wp_error( $eligible ) ) {
			return $eligible;
		}
		$user = $eligible;

		/**
		 * Filter the authenticated user before the auth cookie is set. Return a
		 * WP_Error to veto the sign-in (e.g. from a 2FA plugin).
		 *
		 * @param WP_User              $user   The resolved user.
		 * @param array<string, mixed> $claims The Google id_token claims.
		 */
		$user = apply_filters( 'lean_google_login_authenticated_user', $user, $claims );

		if ( is_wp_error( $user ) ) {
			return $user;
		}
		if ( ! $user instanceof WP_User ) {
			return new WP_Error( 'lean_google_login_rejected', __( 'Sign-in was rejected.', 'lean-google-login' ) );
		}
		return $user;
	}

	/**
	 * Map a verified identity to a WordPress user. The link is keyed on the
	 * stable `sub` first, so a user whose Google email later changes is still
	 * recognized as themselves and never gets a duplicate account. A pre-existing
	 * account is only ever auto-linked to a first-time identity when Google is
	 * authoritative for the email; otherwise auto-provisioning (if enabled) makes
	 * a fresh account.
	 *
	 * @param array<string, mixed> $claims The id_token claims.
	 * @param string               $email  The sanitized email address.
	 * @param string               $sub    The stable Google account id (non-empty).
	 * @return WP_User|WP_Error
	 */
	private static function resolve_user( array $claims, string $email, string $sub ) {
		$linked = self::find_user_by_sub( $sub );
		if ( $linked instanceof WP_User ) {
			return $linked;
		}

		$existing = get_user_by( 'email', $email );
		if ( $existing instanceof WP_User ) {
			$other = (string) get_user_meta( $existing->ID, self::META_SUB, true );
			if ( '' !== $other ) {
				// This email's account is already linked to a different Google
				// account (had it been this one, find_user_by_sub would have hit).
				return new WP_Error( 'lean_google_login_sub_mismatch', __( 'This Google account does not match the WordPress account registered to that email address.', 'lean-google-login' ) );
			}

			// First Google sign-in for a pre-existing account. Binding it hands
			// that account to this Google identity, so only do it when Google is
			// authoritative for the address: a merely "verified" third-party
			// mailbox can change owner while the Google identity persists, which
			// would let a later owner take over the WordPress account.
			if ( ! self::google_is_authoritative( $claims, $email ) ) {
				return new WP_Error( 'lean_google_login_link_unverified', __( 'This email address cannot be automatically linked to the existing account. Sign in to that account first and link Google from your profile.', 'lean-google-login' ) );
			}

			update_user_meta( $existing->ID, self::META_SUB, $sub );
			return $existing;
		}

		if ( ! Lean_Google_Login_Config::get_bool( self::OPTION_AUTO_CREATE, false ) ) {
			return new WP_Error( 'lean_google_login_no_account', __( 'No WordPress account exists for that email address.', 'lean-google-login' ) );
		}

		return self::create_user( $email, $claims, $sub );
	}

	/**
	 * The WordPress user linked to this Google `sub`, or null. The oldest match
	 * wins, so any duplicate accounts left by earlier email-first linking resolve
	 * stably to the original.
	 *
	 * @param string $sub The stable Google account id.
	 */
	private static function find_user_by_sub( string $sub ): ?WP_User {
		if ( '' === $sub ) {
			return null;
		}
		$users = get_users(
			[
				'meta_key'   => self::META_SUB, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Identity lookup keyed on the stable Google sub; indexed by usermeta.
				'meta_value' => $sub,           // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'     => 1,
				'orderby'    => 'ID',
				'order'      => 'ASC',
			]
		);
		return ( ! empty( $users ) && $users[0] instanceof WP_User ) ? $users[0] : null;
	}

	/**
	 * Whether Google is authoritative for this verified email — Workspace
	 * accounts (the domain named in `hd` is Google-managed) and consumer Google
	 * accounts (Google owns the mailbox). A verified address outside these is not
	 * trusted to seize a pre-existing WordPress account on a first sign-in.
	 *
	 * @param array<string, mixed> $claims The id_token claims.
	 * @param string               $email  The sanitized email address.
	 */
	private static function google_is_authoritative( array $claims, string $email ): bool {
		$hd = isset( $claims['hd'] ) ? trim( (string) $claims['hd'] ) : '';
		if ( '' !== $hd ) {
			return true;
		}

		$at            = strrchr( $email, '@' );
		$domain        = false === $at ? '' : strtolower( substr( $at, 1 ) );
		$authoritative = in_array( $domain, [ 'gmail.com', 'googlemail.com' ], true );

		/**
		 * Filter whether Google is authoritative for this verified email, i.e.
		 * whether it may be auto-linked to a pre-existing WordPress account on a
		 * first sign-in. Enable only for domains you know Google manages.
		 *
		 * @param bool                 $authoritative Whether the email is trusted for auto-linking.
		 * @param array<string, mixed> $claims        The id_token claims.
		 * @param string               $email         The sanitized email address.
		 */
		return (bool) apply_filters( 'lean_google_login_email_is_authoritative', $authoritative, $claims, $email );
	}

	/**
	 * Apply core account eligibility to a resolved user before a session is
	 * issued. This federated sign-in never runs the `authenticate` filter chain —
	 * those handlers verify a password we do not have, and replaying them with an
	 * empty password is both wrong and a bypass risk. Instead we run the checks
	 * that are not password-bound: the multisite spam/deleted and membership
	 * gates, and the `wp_authenticate_user` policy filter that account-disable,
	 * suspension and 2FA plugins hook after a password is verified.
	 *
	 * @param WP_User $user The resolved user.
	 * @return WP_User|WP_Error
	 */
	private static function enforce_account_eligibility( WP_User $user ) {
		if ( function_exists( 'wp_authenticate_spam_check' ) ) {
			$checked = wp_authenticate_spam_check( $user );
			if ( is_wp_error( $checked ) ) {
				return $checked;
			}
		}

		if ( is_multisite() ) {
			if ( 1 === (int) $user->deleted || 1 === (int) $user->spam ) {
				return new WP_Error( 'lean_google_login_account_blocked', __( 'This account is not permitted to sign in.', 'lean-google-login' ) );
			}
			if ( ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
				return new WP_Error( 'lean_google_login_not_a_member', __( 'This account is not a member of this site.', 'lean-google-login' ) );
			}
		}

		// Core applies this filter after a verified password; account-policy and
		// 2FA plugins hook it to allow or deny a sign-in. We pass no password.
		$checked = apply_filters( 'wp_authenticate_user', $user, '' );
		if ( is_wp_error( $checked ) ) {
			return $checked;
		}
		if ( ! $checked instanceof WP_User ) {
			return new WP_Error( 'lean_google_login_rejected', __( 'Sign-in was rejected.', 'lean-google-login' ) );
		}
		return $checked;
	}

	/**
	 * Whether the email in these claims is allowed by the domain allow-list. An
	 * empty allow-list permits any verified Google account.
	 *
	 * Workspace membership is asserted by the `hd` (hosted-domain) claim, not by
	 * the email domain: Google warns that a matching email domain alone does not
	 * prove organizational membership. A matching verified email domain is
	 * therefore accepted only when the `lean_google_login_allow_email_domain_match`
	 * filter opts into that weaker policy.
	 *
	 * @param array<string, mixed> $claims The id_token claims.
	 * @param string               $email  The sanitized email address.
	 */
	public static function domain_allowed( array $claims, string $email ): bool {
		$allowed = self::allowed_domains();
		if ( empty( $allowed ) ) {
			return true;
		}

		$hd = isset( $claims['hd'] ) ? strtolower( trim( (string) $claims['hd'] ) ) : '';
		if ( '' !== $hd && in_array( $hd, $allowed, true ) ) {
			return true;
		}

		/**
		 * Filter whether a matching verified email domain (with no corresponding
		 * `hd` claim) also satisfies the allow-list. Off by default: this is a
		 * weaker signal than Workspace membership.
		 *
		 * @param bool                 $allow  Whether email-domain matching is permitted.
		 * @param array<string, mixed> $claims The id_token claims.
		 * @param string               $email  The sanitized email address.
		 */
		if ( apply_filters( 'lean_google_login_allow_email_domain_match', false, $claims, $email ) ) {
			$at           = strrchr( $email, '@' );
			$email_domain = false === $at ? '' : strtolower( substr( $at, 1 ) );
			if ( '' !== $email_domain && in_array( $email_domain, $allowed, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The configured allow-list as a list of bare, lowercase domains. Accepts a
	 * comma- and/or whitespace-separated string; a leading "@" on an entry is
	 * tolerated.
	 *
	 * @return string[]
	 */
	public static function allowed_domains(): array {
		$raw   = Lean_Google_Login_Config::get_string( self::OPTION_ALLOWED_DOMAINS );
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		if ( ! is_array( $parts ) ) {
			return [];
		}

		$domains = [];
		foreach ( $parts as $part ) {
			$domain = strtolower( ltrim( trim( $part ), '@' ) );
			if ( '' !== $domain ) {
				$domains[] = $domain;
			}
		}
		return array_values( array_unique( $domains ) );
	}

	/**
	 * Create a new WordPress user from a verified Google identity.
	 *
	 * @param string               $email  The sanitized email address.
	 * @param array<string, mixed> $claims The id_token claims.
	 * @param string               $sub    The Google account id to bind.
	 * @return WP_User|WP_Error
	 */
	private static function create_user( string $email, array $claims, string $sub ) {
		// WordPress stores user_login in a column capped at 60 characters, so the
		// generated username must fit — base plus any collision suffix.
		$max_len = 60;

		$local = current( explode( '@', $email ) );
		$base  = substr( sanitize_user( (string) $local, true ), 0, $max_len );
		if ( '' === $base ) {
			$base = 'user';
		}

		$username = $base;
		$suffix   = 1;
		while ( username_exists( $username ) ) {
			$tail     = (string) $suffix;
			$username = substr( $base, 0, $max_len - strlen( $tail ) ) . $tail;
			++$suffix;
		}

		$userdata = [
			'user_login' => $username,
			'user_email' => $email,
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => self::default_role(),
		];
		if ( ! empty( $claims['given_name'] ) ) {
			$userdata['first_name'] = sanitize_text_field( (string) $claims['given_name'] );
		}
		if ( ! empty( $claims['family_name'] ) ) {
			$userdata['last_name'] = sanitize_text_field( (string) $claims['family_name'] );
		}
		if ( ! empty( $claims['name'] ) ) {
			$userdata['display_name'] = sanitize_text_field( (string) $claims['name'] );
		}

		$user_id = wp_insert_user( $userdata );
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		if ( '' !== $sub ) {
			update_user_meta( $user_id, self::META_SUB, $sub );
		}

		$user = get_user_by( 'id', $user_id );
		return $user instanceof WP_User ? $user : new WP_Error( 'lean_google_login_create_failed', __( 'The new account could not be loaded after creation.', 'lean-google-login' ) );
	}

	/**
	 * The role assigned to auto-created users: the configured role when it is a
	 * real role, otherwise WordPress's own default-role setting.
	 */
	public static function default_role(): string {
		$role = Lean_Google_Login_Config::get_string( self::OPTION_DEFAULT_ROLE );
		if ( '' !== $role && wp_roles()->is_role( $role ) ) {
			return $role;
		}
		$fallback = (string) get_option( 'default_role', 'subscriber' );
		return '' !== $fallback ? $fallback : 'subscriber';
	}

	/**
	 * Accept the several shapes a JSON boolean survives as once it has passed
	 * through json_decode and WordPress: real bool, '1'/'true'/'yes'.
	 *
	 * @param mixed $value
	 */
	private static function claim_is_true( $value ): bool {
		if ( is_bool( $value ) ) {
			return $value;
		}
		return in_array( strtolower( trim( (string) $value ) ), [ '1', 'true', 'yes' ], true );
	}

	// -------------------------------------------------------------------------
	// Login screen
	// -------------------------------------------------------------------------

	/**
	 * The "Sign in with Google" button, rendered inside the wp-login.php form.
	 * Nothing is shown until an OAuth client is configured.
	 */
	public static function render_button(): void {
		if ( ! Lean_Google_Login_Client::is_configured() ) {
			return;
		}

		$url = add_query_arg(
			array_filter(
				[
					'action'      => self::START_ACTION,
					'redirect_to' => self::requested_redirect_to(),
				]
			),
			admin_url( 'admin-post.php' )
		);

		/**
		 * Filter the button label.
		 *
		 * @param string $label The button text.
		 */
		$label = (string) apply_filters( 'lean_google_login_button_text', __( 'Sign in with Google', 'lean-google-login' ) );
		?>
		<div class="lgl-wrap">
			<div class="lgl-divider"><span><?php esc_html_e( 'or', 'lean-google-login' ); ?></span></div>
			<a class="lgl-button" href="<?php echo esc_url( $url ); ?>">
				<span class="lgl-icon" aria-hidden="true">
					<svg viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg">
						<path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"/>
						<path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/>
						<path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.997 8.997 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/>
						<path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/>
					</svg>
				</span>
				<span class="lgl-label"><?php echo esc_html( $label ); ?></span>
			</a>
		</div>
		<?php
	}

	public static function enqueue_button_css(): void {
		wp_enqueue_style( 'lean-google-login', LEAN_GOOGLE_LOGIN_URL . 'css/login.css', [], LEAN_GOOGLE_LOGIN_VERSION );
	}

	/**
	 * Surface an OAuth failure above the login form. Reads the code the callback
	 * redirected with; the human message is carried alongside it.
	 */
	public static function login_error_message( string $message ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading a redirect flag to display a message; no state change.
		if ( ! isset( $_GET['lgl_error'] ) ) {
			return $message;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading a redirect flag to display a message; no state change.
		$text = isset( $_GET['lgl_msg'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['lgl_msg'] ) ) : '';
		if ( '' === $text ) {
			$text = __( 'Google sign-in failed.', 'lean-google-login' );
		}
		return $message . '<div id="login_error" class="notice notice-error"><p>' . esc_html( $text ) . '</p></div>';
	}

	// -------------------------------------------------------------------------
	// Request / cookie helpers
	// -------------------------------------------------------------------------

	/**
	 * A sanitized $_GET value. The OAuth callback is anonymous, so there is no
	 * nonce to verify — the state cookie checked in handle_callback() is the CSRF
	 * defense — hence the single ignore here rather than at every call site.
	 */
	private static function get_param( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Anonymous OAuth callback; CSRF is defended by the state cookie, not a WP nonce.
		return isset( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : '';
	}

	/**
	 * The requested post-login destination, as a raw URL. Validated to the local
	 * host only at the point of redirect, via wp_safe_redirect.
	 */
	private static function requested_redirect_to(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading the login redirect target; validated by wp_safe_redirect at use.
		return isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_GET['redirect_to'] ) ) : '';
	}

	private static function state_cookie_name(): string {
		// __Host- requires Secure + path=/ + no Domain, so it is only usable over HTTPS.
		return is_ssl() ? '__Host-lgl_state' : 'lgl_state';
	}

	private static function cookie_options( int $expires ): array {
		$ssl = is_ssl();
		return [
			'expires'  => $expires,
			'path'     => $ssl ? '/' : ( defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/' ),
			'domain'   => $ssl ? '' : ( defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '' ),
			'secure'   => $ssl,
			'httponly' => true,
			'samesite' => 'Lax',
		];
	}

	private static function set_state_cookie( string $state ): void {
		setcookie( self::state_cookie_name(), $state, self::cookie_options( time() + self::STATE_TTL ) );
	}

	private static function read_state_cookie(): string {
		$name = self::state_cookie_name();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The cookie IS the CSRF token; it is compared with hash_equals in handle_callback().
		return isset( $_COOKIE[ $name ] ) ? sanitize_text_field( wp_unslash( (string) $_COOKIE[ $name ] ) ) : '';
	}

	private static function clear_state_cookie(): void {
		setcookie( self::state_cookie_name(), '', self::cookie_options( time() - 3600 ) );
	}

	/**
	 * Bounce back to wp-login.php carrying an error code and message, then stop.
	 */
	private static function redirect_to_login( string $code, string $message = '' ): void {
		$args = [ 'lgl_error' => $code ];
		if ( '' !== $message ) {
			$args['lgl_msg'] = rawurlencode( $message );
		}
		wp_safe_redirect( add_query_arg( $args, wp_login_url() ) );
		exit;
	}
}
