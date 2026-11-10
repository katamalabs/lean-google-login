<?php
/**
 * Tests for the Google OAuth client.
 *
 * The pure pieces — the consent URL builder and the id_token claim reader — are
 * checked without a network. The code exchange is exercised with the HTTP layer
 * mocked via pre_http_request.
 *
 * @package lean-google-login
 */

class Test_Lean_Google_Login_Client extends WP_UnitTestCase {

	const CLIENT_ID     = '1234567890-abc.apps.googleusercontent.com';
	const CLIENT_SECRET = 'GOCSPX-secret';

	public function tear_down() {
		remove_all_filters( 'pre_http_request' );
		parent::tear_down();
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	private static function b64url( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * A minimal JWT carrying the given claims as its payload. The signature is a
	 * placeholder — the client never verifies it, it only reads the payload.
	 *
	 * @param array<string, mixed> $claims
	 */
	private static function id_token( array $claims ): string {
		return self::b64url( '{"alg":"RS256"}' ) . '.' . self::b64url( (string) wp_json_encode( $claims ) ) . '.sig';
	}

	/**
	 * Mock the token endpoint with a canned response.
	 */
	private function mock_token( int $code, string $body, ?int &$hits = null ): void {
		$hits = 0;
		add_filter(
			'pre_http_request',
			function ( $preempt, $args, $url ) use ( $code, $body, &$hits ) {
				if ( Lean_Google_Login_Client::TOKEN_URI === $url ) {
					++$hits;
					return [
						'response' => [
							'code'    => $code,
							'message' => '',
						],
						'body'     => $body,
					];
				}
				return $preempt;
			},
			10,
			3
		);
	}

	// -------------------------------------------------------------------------
	// Pure: authorize_url
	// -------------------------------------------------------------------------

	public function test_authorize_url_carries_the_login_parameters() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_ID, self::CLIENT_ID );

		$url = Lean_Google_Login_Client::authorize_url( 'https://site.example/wp-admin/admin-post.php?action=cb', 'state-123' );

		$this->assertStringStartsWith( Lean_Google_Login_Client::AUTH_URI . '?', $url );
		$this->assertStringContainsString( 'response_type=code', $url );
		$this->assertStringContainsString( 'access_type=online', $url );
		$this->assertStringContainsString( 'prompt=select_account', $url );
		$this->assertStringContainsString( 'state=state-123', $url );
		$this->assertStringContainsString( 'client_id=' . rawurlencode( self::CLIENT_ID ), $url );
		// Scope is space-delimited and RFC3986-encoded (spaces as %20, not +).
		$this->assertStringContainsString( 'scope=openid%20email%20profile', $url );
		$this->assertStringNotContainsString( 'scope=openid+email', $url );
		$this->assertStringContainsString( 'redirect_uri=' . rawurlencode( 'https://site.example/wp-admin/admin-post.php?action=cb' ), $url );
		// No hd hint unless one is passed.
		$this->assertStringNotContainsString( 'hd=', $url );
	}

	public function test_authorize_url_includes_the_hd_hint_when_given() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_ID, self::CLIENT_ID );

		$url = Lean_Google_Login_Client::authorize_url( 'https://site.example/cb', 'st', 'example.com' );
		$this->assertStringContainsString( 'hd=example.com', $url );
	}

	// -------------------------------------------------------------------------
	// Pure: claims_from_id_token
	// -------------------------------------------------------------------------

	public function test_claims_from_id_token_reads_the_payload() {
		$token  = self::id_token(
			[
				'email'          => 'user@example.com',
				'email_verified' => true,
				'hd'             => 'example.com',
				'sub'            => '117',
			]
		);
		$claims = Lean_Google_Login_Client::claims_from_id_token( $token );

		$this->assertSame( 'user@example.com', $claims['email'] );
		$this->assertSame( 'example.com', $claims['hd'] );
		$this->assertSame( '117', $claims['sub'] );
	}

	public function test_claims_from_id_token_returns_empty_on_garbage() {
		$this->assertSame( [], Lean_Google_Login_Client::claims_from_id_token( 'not-a-jwt' ) );
		$this->assertSame( [], Lean_Google_Login_Client::claims_from_id_token( self::b64url( 'x' ) . '.' . self::b64url( 'not-json' ) . '.sig' ) );
	}

	// -------------------------------------------------------------------------
	// Code exchange (mocked)
	// -------------------------------------------------------------------------

	public function test_exchange_code_returns_the_claims_on_success() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_ID, self::CLIENT_ID );
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, self::CLIENT_SECRET );

		$id_token = self::id_token(
			[
				'email'          => 'user@example.com',
				'email_verified' => true,
				'sub'            => '42',
			]
		);
		$this->mock_token( 200, (string) wp_json_encode( [ 'id_token' => $id_token ] ), $hits );

		$claims = Lean_Google_Login_Client::exchange_code( 'auth-code', 'https://site.example/cb' );

		$this->assertIsArray( $claims );
		$this->assertSame( 'user@example.com', $claims['email'] );
		$this->assertSame( '42', $claims['sub'] );
		$this->assertSame( 1, $hits );
	}

	public function test_exchange_code_reports_a_google_error() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_ID, self::CLIENT_ID );
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, self::CLIENT_SECRET );

		$this->mock_token( 400, '{"error":"invalid_grant","error_description":"Malformed auth code."}' );

		$result = Lean_Google_Login_Client::exchange_code( 'bad-code', 'https://site.example/cb' );

		$this->assertWPError( $result );
		$this->assertStringContainsString( 'Malformed auth code.', $result->get_error_message() );
	}

	public function test_exchange_code_errors_when_no_id_token_is_returned() {
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_ID, self::CLIENT_ID );
		update_option( Lean_Google_Login_Client::OPTION_CLIENT_SECRET, self::CLIENT_SECRET );

		$this->mock_token( 200, '{"access_token":"tok"}' );

		$result = Lean_Google_Login_Client::exchange_code( 'auth-code', 'https://site.example/cb' );
		$this->assertWPError( $result );
	}
}
