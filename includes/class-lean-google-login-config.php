<?php
/**
 * Setting resolution: a `wp-config.php` constant beats the stored option.
 *
 * Every setting the plugin reads goes through here, so any of them can be
 * pinned in `wp-config.php` instead of the database — the usual want on a
 * self-managed, version-controlled site with more than one environment:
 *
 *     define( 'LEAN_GOOGLE_LOGIN_CLIENT_ID', '1234.apps.googleusercontent.com' );
 *     define( 'LEAN_GOOGLE_LOGIN_CLIENT_SECRET', getenv( 'GOOGLE_OAUTH_SECRET' ) );
 *     define( 'LEAN_GOOGLE_LOGIN_ALLOWED_DOMAINS', 'example.com' );
 *
 * The constant name is simply the option name uppercased, so a new setting
 * gets constant support for free. A secret held in a constant is plaintext by
 * definition and is never run through Lean_Google_Login_Crypto.
 *
 * A constant-backed setting is locked: the settings page renders it read-only
 * and its sanitize callback leaves the stored option untouched, so the two
 * never drift into disagreeing about what is actually in force.
 *
 * Trimmed from Lean SMTP's config: this plugin stores plain site options and
 * has no network (sitemeta) store — the configuration is small and per-site.
 *
 * @package lean-google-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Lean_Google_Login_Config {

	/**
	 * Plugin-infrastructure constants that share the LEAN_GOOGLE_LOGIN_ prefix
	 * but are not settings. No option is named after any of them; the guard just
	 * means a future one can't silently start overriding a setting.
	 */
	private const RESERVED = [ 'LEAN_GOOGLE_LOGIN_VERSION', 'LEAN_GOOGLE_LOGIN_FILE', 'LEAN_GOOGLE_LOGIN_DIR', 'LEAN_GOOGLE_LOGIN_URL' ];

	public static function constant_name( string $option ): string {
		return strtoupper( $option );
	}

	/**
	 * Whether this setting is pinned by a constant (and so locked in the UI).
	 */
	public static function is_constant( string $option ): bool {
		$name = self::constant_name( $option );
		return ! in_array( $name, self::RESERVED, true ) && defined( $name );
	}

	/**
	 * The value in force: constant if defined, otherwise the stored option.
	 *
	 * @param mixed $default Returned when neither a constant nor the option exists.
	 * @return mixed
	 */
	public static function get( string $option, $default = '' ) {
		if ( self::is_constant( $option ) ) {
			return constant( self::constant_name( $option ) );
		}
		return self::stored( $option, $default );
	}

	/**
	 * The raw stored value — no constant lookup, no decryption. The single place
	 * get_option is called, so reads here and the guard's writes can't drift.
	 *
	 * @param mixed $default Returned when the option does not exist.
	 * @return mixed
	 */
	public static function stored( string $option, $default = '' ) {
		return get_option( $option, $default );
	}

	public static function get_string( string $option, string $default = '' ): string {
		return trim( (string) self::get( $option, $default ) );
	}

	/**
	 * Booleans are stored as '1'/'0' but are naturally `true`/`false` when they
	 * come from a constant, so accept both spellings.
	 */
	public static function get_bool( string $option, bool $default = false ): bool {
		$value = self::get( $option, $default ? '1' : '0' );
		if ( is_bool( $value ) ) {
			return $value;
		}
		return in_array( strtolower( trim( (string) $value ) ), [ '1', 'true', 'yes', 'on' ], true );
	}

	/**
	 * A stored secret, decrypted. A constant holds it in plaintext already.
	 */
	public static function get_secret( string $option ): string {
		if ( self::is_constant( $option ) ) {
			return trim( (string) constant( self::constant_name( $option ) ) );
		}
		return Lean_Google_Login_Crypto::decrypt( (string) self::stored( $option, '' ) );
	}

	/**
	 * Whether a secret is set, without decrypting it — for rendering the
	 * "leave blank to keep" placeholder on a field that never echoes its value.
	 */
	public static function has_secret( string $option ): bool {
		if ( self::is_constant( $option ) ) {
			return '' !== trim( (string) constant( self::constant_name( $option ) ) );
		}
		return '' !== (string) self::stored( $option, '' );
	}
}
