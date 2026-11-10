<?php
/**
 * Settings → Lean Google Login: the OAuth client credentials, the optional
 * domain allow-list, and the auto-create / default-role options.
 *
 * Any setting can instead be pinned in wp-config.php (see
 * Lean_Google_Login_Config). When it is, the field renders read-only and
 * guard_constant() discards the submission — so what the page shows is always
 * what is in force, and removing the constant restores whatever was saved
 * before. The field renderers and the register_setting / guard_constant pattern
 * are ports of Lean SMTP's.
 *
 * @package lean-google-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Lean_Google_Login_Settings {

	const PAGE  = 'lean-google-login';
	const GROUP = 'lean-google-login-group';

	/** Hook suffix of the settings screen, so assets load nowhere else. */
	private static string $settings_hook = '';

	public static function init(): void {
		add_action( 'admin_menu', [ static::class, 'admin_menu' ] );
		add_action( 'admin_init', [ static::class, 'register_settings' ] );
		add_action( 'admin_enqueue_scripts', [ static::class, 'enqueue_assets' ] );
		add_filter( 'plugin_action_links_' . plugin_basename( LEAN_GOOGLE_LOGIN_FILE ), [ static::class, 'settings_link' ] );
	}

	/**
	 * A URL to the settings screen.
	 *
	 * @param array $args Extra query arguments.
	 */
	public static function url( array $args = [] ): string {
		$url = admin_url( 'options-general.php?page=' . rawurlencode( self::PAGE ) );
		return empty( $args ) ? $url : add_query_arg( $args, $url );
	}

	public static function settings_link( array $links ): array {
		$links[] = '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Settings', 'lean-google-login' ) . '</a>';
		return $links;
	}

	public static function admin_menu(): void {
		self::$settings_hook = (string) add_options_page(
			__( 'Lean Google Login', 'lean-google-login' ),
			__( 'Lean Google Login', 'lean-google-login' ),
			'manage_options',
			self::PAGE,
			[ static::class, 'settings_page' ]
		);
	}

	public static function enqueue_assets( string $hook_suffix ): void {
		if ( '' === self::$settings_hook || $hook_suffix !== self::$settings_hook ) {
			return;
		}
		wp_enqueue_style( 'lean-google-login-settings', LEAN_GOOGLE_LOGIN_URL . 'css/settings.css', [], LEAN_GOOGLE_LOGIN_VERSION );
	}

	// -------------------------------------------------------------------------
	// Registration & sanitizing
	// -------------------------------------------------------------------------

	/**
	 * Register every setting this page owns, each with the sanitize callback its
	 * submitted value has to pass through. Spelled out one call per setting
	 * rather than looped, so the sanitizer in force is readable at registration
	 * and WordPress.org review can resolve each callback to a literal.
	 */
	public static function register_settings(): void {
		register_setting( self::GROUP, Lean_Google_Login_Client::OPTION_CLIENT_ID, [ 'sanitize_callback' => 'sanitize_text_field' ] );
		register_setting( self::GROUP, Lean_Google_Login_Client::OPTION_CLIENT_SECRET, [ 'sanitize_callback' => [ static::class, 'sanitize_client_secret' ] ] );
		register_setting( self::GROUP, Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, [ 'sanitize_callback' => [ static::class, 'sanitize_allowed_domains' ] ] );
		register_setting( self::GROUP, Lean_Google_Login_Auth::OPTION_AUTO_CREATE, [ 'sanitize_callback' => 'absint' ] );
		register_setting( self::GROUP, Lean_Google_Login_Auth::OPTION_DEFAULT_ROLE, [ 'sanitize_callback' => [ static::class, 'sanitize_role' ] ] );

		self::guard_constant_backed_settings();
	}

	/**
	 * Layer the wp-config.php constant guard on top of every sanitize callback,
	 * at a later priority so it has the last word. The option list is read back
	 * out of core's registry for this group, so a newly registered setting is
	 * guarded automatically.
	 */
	private static function guard_constant_backed_settings(): void {
		$options = $GLOBALS['new_allowed_options'][ self::GROUP ] ?? [];
		foreach ( (array) $options as $option ) {
			add_filter( "sanitize_option_{$option}", [ static::class, 'guard_constant' ], 20, 2 );
		}
	}

	/**
	 * Keep a constant-backed setting immune to form submissions. Necessary as
	 * well as tidy: core's options.php calls update_option() with null for any
	 * registered option missing from the POST, so a disabled field alone would
	 * wipe the value saved underneath the constant.
	 *
	 * @param mixed  $value  The sanitized value.
	 * @param string $option The option being saved.
	 * @return mixed
	 */
	public static function guard_constant( $value, string $option = '' ) {
		if ( '' !== $option && Lean_Google_Login_Config::is_constant( $option ) ) {
			return Lean_Google_Login_Config::stored( $option, '' );
		}
		return $value;
	}

	public static function sanitize_client_secret( $value ): string {
		return self::sanitize_secret( $value, Lean_Google_Login_Client::OPTION_CLIENT_SECRET );
	}

	/**
	 * A secret (the OAuth client secret) is an opaque token, so it is deliberately
	 * not run through sanitize_text_field(), which would strip characters legal in
	 * a secret and leave it silently non-authenticating. Only control characters
	 * are removed, then the value is encrypted. A blank submission keeps the stored
	 * value (so re-saving never wipes a secret the field doesn't echo); the "clear"
	 * checkbox beside the field removes it deliberately.
	 *
	 * @param mixed  $value  Submitted value.
	 * @param string $option Option being sanitized.
	 */
	private static function sanitize_secret( $value, string $option ): string {
		$value = is_string( $value ) ? trim( $value ) : '';
		if ( '' === $value ) {
			return self::secret_cleared( $option ) ? '' : (string) Lean_Google_Login_Config::stored( $option, '' );
		}
		// WordPress runs the callback twice on a first save (update then add); the
		// second pass receives our own ciphertext — don't encrypt it again.
		if ( Lean_Google_Login_Crypto::is_encrypted( $value ) ) {
			return $value;
		}
		$stripped = preg_replace( '/[\x00-\x1F\x7F]/', '', $value );
		return Lean_Google_Login_Crypto::encrypt( trim( is_string( $stripped ) ? $stripped : $value ) );
	}

	/**
	 * Whether the "clear" checkbox beside a secret field was ticked on this save.
	 * options.php has already verified this option group's nonce before any
	 * sanitize callback runs.
	 */
	private static function secret_cleared( string $option ): bool {
		$field = $option . '__clear';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- options.php verified the settings-group nonce before this sanitize callback ran.
		$value = isset( $_POST[ $field ] ) ? sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) : '';
		return '1' === $value;
	}

	/**
	 * Normalize the domain allow-list to a comma-separated list of bare,
	 * lowercase domains, discarding anything that isn't a plausible hostname.
	 *
	 * @param mixed $value Submitted value.
	 */
	public static function sanitize_allowed_domains( $value ): string {
		$value = is_string( $value ) ? $value : '';
		$parts = preg_split( '/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY );
		if ( ! is_array( $parts ) || empty( $parts ) ) {
			// The field was cleared on purpose: no restriction.
			return '';
		}

		$domains = [];
		$invalid = [];
		foreach ( $parts as $part ) {
			$domain = strtolower( ltrim( trim( $part ), '@' ) );
			if ( '' === $domain ) {
				continue;
			}
			// A permissive hostname check: letters/digits/hyphens in dot-separated labels.
			if ( preg_match( '/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain ) ) {
				$domains[ $domain ] = true;
			} else {
				$invalid[] = $domain;
			}
		}

		// A non-empty submission that normalizes to nothing would, if saved as an
		// empty string, silently REMOVE the restriction and let every Google
		// domain in. Refuse that: warn, and keep whatever was stored before. To
		// lift the restriction the admin must clear the field entirely.
		if ( ! empty( $invalid ) ) {
			add_settings_error(
				Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS,
				'lean_google_login_invalid_domain',
				sprintf(
					/* translators: %s: the rejected entries. */
					__( 'These allowed-domain entries are not valid hostnames and were ignored: %s. To remove the restriction entirely, clear the field.', 'lean-google-login' ),
					esc_html( implode( ', ', $invalid ) )
				)
			);
		}

		if ( empty( $domains ) ) {
			return (string) Lean_Google_Login_Config::stored( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, '' );
		}

		return implode( ', ', array_keys( $domains ) );
	}

	/**
	 * Keep the default-role setting to an existing role; fall back to empty (which
	 * the auth layer resolves to WordPress's own default role).
	 *
	 * @param mixed $value Submitted value.
	 */
	public static function sanitize_role( $value ): string {
		$role = is_string( $value ) ? sanitize_key( $value ) : '';
		return ( '' !== $role && wp_roles()->is_role( $role ) ) ? $role : '';
	}

	// -------------------------------------------------------------------------
	// Field helpers
	// -------------------------------------------------------------------------

	private static function lock_note( string $option ): void {
		if ( ! Lean_Google_Login_Config::is_constant( $option ) ) {
			return;
		}
		?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: PHP constant name. */
				esc_html__( 'Set in wp-config.php as %s — change it there.', 'lean-google-login' ),
				'<code>' . esc_html( Lean_Google_Login_Config::constant_name( $option ) ) . '</code>'
			);
			?>
		</p>
		<?php
	}

	/**
	 * @param array $args type, class, placeholder, description, value.
	 */
	private static function text_field( string $option, array $args = [] ): void {
		$args  = wp_parse_args(
			$args,
			[
				'type'        => 'text',
				'class'       => 'regular-text',
				'placeholder' => '',
				'description' => '',
			]
		);
		$value = array_key_exists( 'value', $args ) ? (string) $args['value'] : (string) Lean_Google_Login_Config::get( $option, '' );
		?>
		<input type="<?php echo esc_attr( $args['type'] ); ?>" id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>" value="<?php echo esc_attr( $value ); ?>"
			class="<?php echo esc_attr( $args['class'] ); ?>" placeholder="<?php echo esc_attr( $args['placeholder'] ); ?>"
			autocomplete="off" <?php disabled( Lean_Google_Login_Config::is_constant( $option ) ); ?> />
		<?php if ( '' !== $args['description'] ) : ?>
			<p class="description"><?php echo esc_html( $args['description'] ); ?></p>
		<?php endif; ?>
		<?php
		self::lock_note( $option );
	}

	/**
	 * A secret never round-trips to the browser: the field renders empty and a
	 * blank submission keeps whatever is stored.
	 */
	private static function secret_field( string $option, string $description = '' ): void {
		$placeholder = Lean_Google_Login_Config::has_secret( $option )
			? __( '••••••••  (leave blank to keep)', 'lean-google-login' )
			: '';
		?>
		<input type="password" id="<?php echo esc_attr( $option ); ?>" name="<?php echo esc_attr( $option ); ?>"
			value="" class="regular-text" autocomplete="new-password"
			placeholder="<?php echo esc_attr( $placeholder ); ?>"
			<?php disabled( Lean_Google_Login_Config::is_constant( $option ) ); ?> />
		<?php
		self::clear_checkbox( $option );
		if ( '' !== $description ) :
			?>
			<p class="description"><?php echo esc_html( $description ); ?></p>
			<?php
		endif;
		self::lock_note( $option );
	}

	private static function clear_checkbox( string $option ): void {
		if ( Lean_Google_Login_Config::is_constant( $option ) || ! Lean_Google_Login_Config::has_secret( $option ) ) {
			return;
		}
		?>
		<label class="lgl-clear-secret">
			<input type="checkbox" name="<?php echo esc_attr( $option ); ?>__clear" value="1" />
			<?php esc_html_e( 'Clear the saved value on save', 'lean-google-login' ); ?>
		</label>
		<?php
	}

	private static function checkbox_field( string $option, string $label, bool $default = false ): void {
		$locked = Lean_Google_Login_Config::is_constant( $option );
		if ( ! $locked ) :
			?>
			<input type="hidden" name="<?php echo esc_attr( $option ); ?>" value="0" />
			<?php
		endif;
		?>
		<label>
			<input type="checkbox" name="<?php echo esc_attr( $option ); ?>" value="1"
				<?php checked( Lean_Google_Login_Config::get_bool( $option, $default ) ); ?>
				<?php disabled( $locked ); ?> />
			<?php echo esc_html( $label ); ?>
		</label>
		<?php
		self::lock_note( $option );
	}

	/**
	 * @param array<string, string> $choices Value => label.
	 */
	private static function select_field( string $option, array $choices, string $default, string $description = '' ): void {
		$current = Lean_Google_Login_Config::get_string( $option, $default );
		?>
		<select id="<?php echo esc_attr( $option ); ?>" name="<?php echo esc_attr( $option ); ?>"
			<?php disabled( Lean_Google_Login_Config::is_constant( $option ) ); ?>>
			<?php foreach ( $choices as $value => $label ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $current, $value ); ?>>
					<?php echo esc_html( $label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
		<?php if ( '' !== $description ) : ?>
			<p class="description"><?php echo esc_html( $description ); ?></p>
		<?php endif; ?>
		<?php
		self::lock_note( $option );
	}

	/**
	 * Installed roles as value => display-name, for the default-role picker.
	 *
	 * @return array<string, string>
	 */
	private static function role_choices(): array {
		$choices = [];
		foreach ( get_editable_roles() as $slug => $details ) {
			$choices[ $slug ] = translate_user_role( $details['name'] );
		}
		return $choices;
	}

	// -------------------------------------------------------------------------
	// Page
	// -------------------------------------------------------------------------

	public static function settings_page(): void {
		$configured = Lean_Google_Login_Client::is_configured();
		?>
		<div class="wrap lgl-wrap">
			<h1><?php esc_html_e( 'Lean Google Login', 'lean-google-login' ); ?></h1>
			<p class="description"><?php esc_html_e( 'Adds a "Sign in with Google" button to the login screen. Password login is left enabled.', 'lean-google-login' ); ?></p>

			<?php
			// WordPress auto-renders settings errors on a page added via
			// add_options_page(), so settings_errors() is deliberately NOT called
			// here — doing so would print "Settings saved." twice.
			?>

			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( self::GROUP ); ?>

				<div class="lgl-card">
					<h2><?php esc_html_e( 'Google OAuth client', 'lean-google-login' ); ?></h2>
					<p class="description">
						<?php esc_html_e( 'Create an OAuth 2.0 "Web application" client in the Google Cloud Console, then paste its credentials here. Only the non-sensitive openid / email / profile scopes are used, so no Google verification is required.', 'lean-google-login' ); ?>
					</p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="<?php echo esc_attr( Lean_Google_Login_Client::OPTION_CLIENT_ID ); ?>"><?php esc_html_e( 'Client ID', 'lean-google-login' ); ?></label></th>
							<td><?php self::text_field( Lean_Google_Login_Client::OPTION_CLIENT_ID, [ 'placeholder' => '1234567890-abc.apps.googleusercontent.com' ] ); ?></td>
						</tr>
						<tr>
							<th scope="row"><label for="<?php echo esc_attr( Lean_Google_Login_Client::OPTION_CLIENT_SECRET ); ?>"><?php esc_html_e( 'Client Secret', 'lean-google-login' ); ?></label></th>
							<td><?php self::secret_field( Lean_Google_Login_Client::OPTION_CLIENT_SECRET ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Authorized redirect URI', 'lean-google-login' ); ?></th>
							<td>
								<input type="text" class="regular-text code" readonly onfocus="this.select()"
									value="<?php echo esc_attr( Lean_Google_Login_Client::redirect_uri() ); ?>" />
								<p class="description"><?php esc_html_e( 'Add this exact URI to your OAuth client\'s "Authorized redirect URIs" in Google Cloud.', 'lean-google-login' ); ?></p>
							</td>
						</tr>
					</table>
				</div>

				<div class="lgl-card">
					<h2><?php esc_html_e( 'Access', 'lean-google-login' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="<?php echo esc_attr( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS ); ?>"><?php esc_html_e( 'Allowed domains', 'lean-google-login' ); ?></label></th>
							<td>
								<?php
								self::text_field(
									Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS,
									[
										'class'       => 'regular-text',
										'placeholder' => 'example.com, example.org',
										'description' => __( 'Comma-separated. Only Google accounts in these domains may sign in. Leave blank to allow any verified Google account.', 'lean-google-login' ),
									]
								);
								?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'New users', 'lean-google-login' ); ?></th>
							<td>
								<?php self::checkbox_field( Lean_Google_Login_Auth::OPTION_AUTO_CREATE, __( 'Create a WordPress account the first time an allowed Google user signs in', 'lean-google-login' ), false ); ?>
								<p class="description"><?php esc_html_e( 'Off by default: only people who already have an account can sign in.', 'lean-google-login' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="<?php echo esc_attr( Lean_Google_Login_Auth::OPTION_DEFAULT_ROLE ); ?>"><?php esc_html_e( 'Role for new users', 'lean-google-login' ); ?></label></th>
							<td>
								<?php
								self::select_field(
									Lean_Google_Login_Auth::OPTION_DEFAULT_ROLE,
									self::role_choices(),
									get_option( 'default_role', 'subscriber' ),
									__( 'Applied only when new-user creation is enabled above.', 'lean-google-login' )
								);
								?>
							</td>
						</tr>
					</table>
				</div>

				<?php submit_button(); ?>
			</form>

			<?php if ( ! $configured ) : ?>
				<p class="description"><?php esc_html_e( 'The sign-in button appears on the login screen once a client ID and secret are saved.', 'lean-google-login' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}
}
