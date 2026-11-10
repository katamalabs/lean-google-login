<?php
/**
 * Tests for the settings sanitizers, the constant guard, and registration.
 *
 * @package lean-google-login
 */

class Test_Lean_Google_Login_Settings extends WP_UnitTestCase {

	const PIN_OPTION = 'lean_google_login_test_pin';

	public function tear_down() {
		unset( $_POST[ Lean_Google_Login_Client::OPTION_CLIENT_SECRET . '__clear' ] );
		parent::tear_down();
	}

	// -------------------------------------------------------------------------
	// Secret sanitizing
	// -------------------------------------------------------------------------

	public function test_a_new_secret_is_stored_encrypted() {
		$stored = Lean_Google_Login_Settings::sanitize_client_secret( 'GOCSPX-value' );

		$this->assertTrue( Lean_Google_Login_Crypto::is_encrypted( $stored ) );
		$this->assertSame( 'GOCSPX-value', Lean_Google_Login_Crypto::decrypt( $stored ) );
	}

	public function test_a_blank_submission_keeps_the_stored_secret() {
		$existing = Lean_Google_Login_Crypto::encrypt( 'keep-me' );
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, $existing );

		$this->assertSame( $existing, Lean_Google_Login_Settings::sanitize_client_secret( '' ) );
	}

	public function test_the_clear_checkbox_empties_a_stored_secret() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, Lean_Google_Login_Crypto::encrypt( 'remove-me' ) );
		$_POST[ Lean_Google_Login_Client::OPTION_CLIENT_SECRET . '__clear' ] = '1';

		$this->assertSame( '', Lean_Google_Login_Settings::sanitize_client_secret( '' ) );
	}

	public function test_already_encrypted_input_is_not_re_encrypted() {
		// WordPress runs the sanitizer twice on a first save; the second pass sees
		// our own ciphertext and must leave it alone.
		$cipher = Lean_Google_Login_Crypto::encrypt( 'once' );
		$this->assertSame( $cipher, Lean_Google_Login_Settings::sanitize_client_secret( $cipher ) );
	}

	// -------------------------------------------------------------------------
	// Domain + role sanitizing
	// -------------------------------------------------------------------------

	public function test_allowed_domains_are_normalized_and_junk_dropped() {
		$out = Lean_Google_Login_Settings::sanitize_allowed_domains( 'Example.com, @Foo.org  bar  example.com' );
		// 'bar' is not a valid domain (no dot/TLD) and is dropped; duplicates collapse.
		$this->assertSame( 'example.com, foo.org', $out );
	}

	public function test_role_sanitizer_keeps_real_roles_and_rejects_others() {
		$this->assertSame( 'editor', Lean_Google_Login_Settings::sanitize_role( 'editor' ) );
		$this->assertSame( '', Lean_Google_Login_Settings::sanitize_role( 'not-a-role' ) );
	}

	// -------------------------------------------------------------------------
	// Constant guard
	// -------------------------------------------------------------------------

	public function test_guard_returns_the_stored_value_for_a_constant_backed_setting() {
		update_option( self::PIN_OPTION, 'stored' );
		// LEAN_GOOGLE_LOGIN_TEST_PIN is defined in the bootstrap, so this option is locked.
		$this->assertSame( 'stored', Lean_Google_Login_Settings::guard_constant( 'submitted', self::PIN_OPTION ) );
	}

	public function test_guard_passes_through_an_unlocked_setting() {
		$this->assertSame( 'submitted', Lean_Google_Login_Settings::guard_constant( 'submitted', 'lean_google_login_client_id' ) );
	}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	public function test_register_settings_registers_the_group() {
		Lean_Google_Login_Settings::register_settings();

		$options = $GLOBALS['new_allowed_options'][ Lean_Google_Login_Settings::GROUP ] ?? [];
		$this->assertContains( Lean_Google_Login_Client::OPTION_CLIENT_ID, (array) $options );
		$this->assertContains( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, (array) $options );
		$this->assertContains( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, (array) $options );
	}
}
