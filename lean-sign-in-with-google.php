<?php
/**
 * Plugin Name: Lean Sign in with Google
 * Plugin URI: https://github.com/katamalabs/lean-sign-in-with-google
 * Description: Free, no upsells, no telemetry. Adds a "Sign in with Google" button to wp-login.php using the OAuth2 authorization-code flow, with an optional Google Workspace domain allow-list, optional auto-provisioning of new users, and wp-config.php overrides. Password login is never disabled.
 * Version: 0.1.0
 * Requires at least: 6.0
 * Requires PHP: 8.1
 * Author: pjaudiomv
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: lean-sign-in-with-google
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'LEAN_SIGN_IN_WITH_GOOGLE_VERSION', '0.1.0' );
define( 'LEAN_SIGN_IN_WITH_GOOGLE_FILE', __FILE__ );
define( 'LEAN_SIGN_IN_WITH_GOOGLE_DIR', plugin_dir_path( __FILE__ ) );
define( 'LEAN_SIGN_IN_WITH_GOOGLE_URL', plugin_dir_url( __FILE__ ) );

require_once LEAN_SIGN_IN_WITH_GOOGLE_DIR . 'includes/class-lean-sign-in-with-google-crypto.php';
require_once LEAN_SIGN_IN_WITH_GOOGLE_DIR . 'includes/class-lean-sign-in-with-google-config.php';
require_once LEAN_SIGN_IN_WITH_GOOGLE_DIR . 'includes/class-lean-sign-in-with-google-client.php';
require_once LEAN_SIGN_IN_WITH_GOOGLE_DIR . 'includes/class-lean-sign-in-with-google-auth.php';
require_once LEAN_SIGN_IN_WITH_GOOGLE_DIR . 'includes/class-lean-sign-in-with-google-settings.php';

class Lean_Sign_In_With_Google {

	private static ?self $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		Lean_Sign_In_With_Google_Auth::init();
		Lean_Sign_In_With_Google_Settings::init();
	}

	// -------------------------------------------------------------------------
	// Activation / Deactivation
	// -------------------------------------------------------------------------

	/**
	 * Nothing to provision on activation: the plugin stores only options and
	 * sets no schedule. Declared so the hooks below have a target and a future
	 * need has an obvious home.
	 */
	public static function activate(): void {
	}

	public static function deactivate(): void {
	}
}

register_activation_hook( __FILE__, [ 'Lean_Sign_In_With_Google', 'activate' ] );
register_deactivation_hook( __FILE__, [ 'Lean_Sign_In_With_Google', 'deactivate' ] );
Lean_Sign_In_With_Google::get_instance();
