<?php
/**
 * Tests for the secret-at-rest crypto.
 *
 * @package lean-sign-in-with-google
 */

class Test_Lean_Sign_In_With_Google_Crypto extends WP_UnitTestCase {

	public function test_encrypt_then_decrypt_round_trips() {
		$plain  = 'GOCSPX-super-secret-value';
		$cipher = Lean_Sign_In_With_Google_Crypto::encrypt( $plain );

		$this->assertNotSame( $plain, $cipher );
		$this->assertTrue( Lean_Sign_In_With_Google_Crypto::is_encrypted( $cipher ) );
		$this->assertStringStartsWith( Lean_Sign_In_With_Google_Crypto::PREFIX, $cipher );
		$this->assertSame( $plain, Lean_Sign_In_With_Google_Crypto::decrypt( $cipher ) );
	}

	public function test_empty_string_is_passed_through() {
		$this->assertSame( '', Lean_Sign_In_With_Google_Crypto::encrypt( '' ) );
		$this->assertSame( '', Lean_Sign_In_With_Google_Crypto::decrypt( '' ) );
	}

	public function test_a_plaintext_value_without_the_prefix_decrypts_to_itself() {
		// Legacy / openssl-less storage: a value with no prefix is treated as plaintext.
		$this->assertFalse( Lean_Sign_In_With_Google_Crypto::is_encrypted( 'legacy-plain' ) );
		$this->assertSame( 'legacy-plain', Lean_Sign_In_With_Google_Crypto::decrypt( 'legacy-plain' ) );
	}

	public function test_each_encryption_uses_a_fresh_iv() {
		$a = Lean_Sign_In_With_Google_Crypto::encrypt( 'same-input' );
		$b = Lean_Sign_In_With_Google_Crypto::encrypt( 'same-input' );

		$this->assertNotSame( $a, $b, 'A random IV should make two ciphertexts of the same input differ.' );
		$this->assertSame( 'same-input', Lean_Sign_In_With_Google_Crypto::decrypt( $a ) );
		$this->assertSame( 'same-input', Lean_Sign_In_With_Google_Crypto::decrypt( $b ) );
	}
}
