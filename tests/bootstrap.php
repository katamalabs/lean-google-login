<?php
/**
 * PHPUnit bootstrap file for Lean Google Login plugin tests.
 *
 * Uses wp-phpunit/wp-phpunit (installed via Composer) as the test library.
 * WordPress core must be downloaded to WP_CORE_DIR (default: /tmp/wordpress).
 */

putenv( 'WP_PHPUNIT__TESTS_CONFIG=' . __DIR__ . '/wp-tests-config.php' );

$lean_google_login_tests_dir = dirname( __DIR__ ) . '/vendor/wp-phpunit/wp-phpunit';

if ( ! file_exists( "{$lean_google_login_tests_dir}/includes/functions.php" ) ) {
	echo 'Could not find wp-phpunit. Run: composer install' . PHP_EOL;
	exit( 1 );
}

require_once "{$lean_google_login_tests_dir}/includes/functions.php";

// Stand in for a wp-config.php constant so the override path in
// Lean_Google_Login_Config is exercised under test. This is a throwaway option
// no other test depends on, so pinning it here affects nothing else.
define( 'LEAN_GOOGLE_LOGIN_TEST_PIN', 'pinned-value' );

/**
 * Load the plugin being tested.
 */
function lean_google_login_tests_manually_load_plugin() {
	require dirname( __DIR__ ) . '/lean-google-login.php';
}
tests_add_filter( 'muplugins_loaded', 'lean_google_login_tests_manually_load_plugin' );

require "{$lean_google_login_tests_dir}/includes/bootstrap.php";
