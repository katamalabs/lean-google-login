<?php
/**
 * Tests for setting resolution (constant beats option) and secret decryption.
 *
 * @package lean-sign-in-with-google
 */

class Test_Lean_Sign_In_With_Google_Config extends WP_UnitTestCase {

	const PIN_OPTION = 'lean_sign_in_with_google_test_pin';

	public function test_a_stored_option_is_returned_when_no_constant_is_defined() {
		update_option( 'lean_sign_in_with_google_client_id', 'stored-id' );
		$this->assertSame( 'stored-id', Lean_Sign_In_With_Google_Config::get_string( 'lean_sign_in_with_google_client_id' ) );
		$this->assertFalse( Lean_Sign_In_With_Google_Config::is_constant( 'lean_sign_in_with_google_client_id' ) );
	}

	public function test_a_constant_overrides_the_stored_option() {
		// LEAN_SIGN_IN_WITH_GOOGLE_TEST_PIN is defined in the test bootstrap.
		update_option( self::PIN_OPTION, 'stored-wins?' );

		$this->assertTrue( Lean_Sign_In_With_Google_Config::is_constant( self::PIN_OPTION ) );
		$this->assertSame( 'pinned-value', Lean_Sign_In_With_Google_Config::get_string( self::PIN_OPTION ) );
		// The raw stored value is still readable without the constant lookup.
		$this->assertSame( 'stored-wins?', Lean_Sign_In_With_Google_Config::stored( self::PIN_OPTION ) );
	}

	public function test_reserved_infrastructure_constants_are_not_treated_as_settings() {
		$this->assertFalse( Lean_Sign_In_With_Google_Config::is_constant( 'lean_sign_in_with_google_version' ) );
	}

	public function test_get_bool_reads_the_several_truthy_spellings() {
		update_option( 'lean_sign_in_with_google_auto_create', '1' );
		$this->assertTrue( Lean_Sign_In_With_Google_Config::get_bool( 'lean_sign_in_with_google_auto_create' ) );

		update_option( 'lean_sign_in_with_google_auto_create', '0' );
		$this->assertFalse( Lean_Sign_In_With_Google_Config::get_bool( 'lean_sign_in_with_google_auto_create' ) );
	}

	public function test_get_secret_decrypts_a_stored_blob() {
		update_option( 'lean_sign_in_with_google_client_secret', Lean_Sign_In_With_Google_Crypto::encrypt( 'the-secret' ) );
		$this->assertSame( 'the-secret', Lean_Sign_In_With_Google_Config::get_secret( 'lean_sign_in_with_google_client_secret' ) );
		$this->assertTrue( Lean_Sign_In_With_Google_Config::has_secret( 'lean_sign_in_with_google_client_secret' ) );
	}

	public function test_has_secret_is_false_when_unset() {
		$this->assertFalse( Lean_Sign_In_With_Google_Config::has_secret( 'lean_sign_in_with_google_client_secret' ) );
	}
}
