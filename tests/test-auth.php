<?php
/**
 * Tests for the identity-to-user mapping: verified-email gate, domain allow-list,
 * sub account-linking, and optional auto-provisioning.
 *
 * authenticate_claims() is pure of HTTP and cookies, so it is driven directly
 * with option config and the WP user factory.
 *
 * @package lean-google-login
 */

class Test_Lean_Google_Login_Auth extends WP_UnitTestCase {

	private function claims( array $overrides = [] ): array {
		return array_merge(
			[
				'email'          => 'alice@example.com',
				'email_verified' => true,
				// A Workspace identity: `hd` makes Google authoritative for the
				// address, which is what the common paths assume.
				'hd'             => 'example.com',
				'sub'            => 'google-sub-1',
				'given_name'     => 'Alice',
				'family_name'    => 'Smith',
				'name'           => 'Alice Smith',
			],
			$overrides
		);
	}

	// -------------------------------------------------------------------------
	// Gates
	// -------------------------------------------------------------------------

	public function test_missing_email_is_rejected() {
		$result = Lean_Google_Login_Auth::authenticate_claims( [ 'email_verified' => true ] );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_no_email', $result->get_error_code() );
	}

	public function test_unverified_email_is_rejected() {
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'email_verified' => false ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_unverified', $result->get_error_code() );
	}

	public function test_string_true_counts_as_verified() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		$result  = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'email_verified' => 'true' ] ) );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	// -------------------------------------------------------------------------
	// Domain allow-list
	// -------------------------------------------------------------------------

	public function test_domain_outside_the_allow_list_is_rejected() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'allowed.com' );
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims() );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_domain', $result->get_error_code() );
	}

	public function test_domain_in_the_allow_list_by_hd_passes() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'example.com, other.org' );
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims() );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	public function test_a_matching_email_domain_without_hd_is_rejected() {
		// Security: the email domain alone does not prove Workspace membership, so
		// a verified address with no (or a different) `hd` must not pass.
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'example.com' );
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'hd' => '' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_domain', $result->get_error_code() );
	}

	public function test_a_wrong_hd_is_rejected_even_when_the_email_domain_matches() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'example.com' );
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'hd' => 'evil.example' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_domain', $result->get_error_code() );
	}

	public function test_email_domain_match_passes_when_the_opt_in_filter_is_enabled() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'example.com' );
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		// Already linked, so resolution turns on the allow-list alone, not the
		// separate first-time-link authoritativeness check.
		update_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, 'google-sub-1' );

		add_filter( 'lean_google_login_allow_email_domain_match', '__return_true' );
		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'hd' => '' ] ) );
		remove_filter( 'lean_google_login_allow_email_domain_match', '__return_true' );

		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	public function test_domain_allowed_via_the_hd_claim() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'corp.example' );
		$user_id = $this->factory->user->create( [ 'user_email' => 'bob@mail.example' ] );

		$claims = $this->claims(
			[
				'email' => 'bob@mail.example',
				'hd'    => 'corp.example',
				'sub'   => 'sub-bob',
			]
		);
		$result = Lean_Google_Login_Auth::authenticate_claims( $claims );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	public function test_blank_allow_list_permits_any_verified_account() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		$result  = Lean_Google_Login_Auth::authenticate_claims( $this->claims() );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	public function test_domain_allowed_helper_matches_hd_case_insensitively() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'Example.COM' );
		$this->assertTrue( Lean_Google_Login_Auth::domain_allowed( [ 'hd' => 'EXAMPLE.com' ], 'alice@mail.example' ) );
		$this->assertFalse( Lean_Google_Login_Auth::domain_allowed( [ 'hd' => 'nope.com' ], 'alice@example.com' ) );
		// The email domain alone, with no matching `hd`, does not satisfy the list.
		$this->assertFalse( Lean_Google_Login_Auth::domain_allowed( [], 'Alice@EXAMPLE.com' ) );
	}

	// -------------------------------------------------------------------------
	// sub account-linking
	// -------------------------------------------------------------------------

	public function test_first_sign_in_backfills_the_sub_meta() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		$this->assertSame( '', (string) get_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, true ) );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'sub' => 'the-sub' ] ) );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( 'the-sub', (string) get_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, true ) );
	}

	public function test_a_different_sub_for_a_linked_account_is_rejected() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		update_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, 'original-sub' );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'sub' => 'attacker-sub' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_sub_mismatch', $result->get_error_code() );
	}

	public function test_the_matching_sub_for_a_linked_account_passes() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		update_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, 'original-sub' );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'sub' => 'original-sub' ] ) );
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	public function test_claims_without_a_sub_are_rejected() {
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'sub' => '' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_no_sub', $result->get_error_code() );
	}

	public function test_a_returning_user_is_resolved_by_sub_after_an_email_change() {
		// The WordPress account is linked by sub; the Google email has since
		// changed. The user must still resolve to the same account, not be denied
		// or duplicated.
		$user_id = $this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );
		update_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, 'stable-sub' );

		$result = Lean_Google_Login_Auth::authenticate_claims(
			$this->claims(
				[
					'email' => 'alice.new@example.com',
					'sub'   => 'stable-sub',
				]
			)
		);
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
	}

	// -------------------------------------------------------------------------
	// First-time linking safety (non-authoritative email)
	// -------------------------------------------------------------------------

	public function test_a_non_authoritative_email_cannot_auto_link_a_preexisting_account() {
		// A verified but non-Google-authoritative address (no `hd`, not Gmail)
		// must not seize an existing, unlinked WordPress account.
		$this->factory->user->create( [ 'user_email' => 'owner@contractor.example' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims(
			$this->claims(
				[
					'email' => 'owner@contractor.example',
					'hd'    => '',
					'sub'   => 'outsider-sub',
				]
			)
		);
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_link_unverified', $result->get_error_code() );
	}

	public function test_a_gmail_identity_may_auto_link_a_preexisting_account() {
		$user_id = $this->factory->user->create( [ 'user_email' => 'person@gmail.com' ] );

		$result = Lean_Google_Login_Auth::authenticate_claims(
			$this->claims(
				[
					'email' => 'person@gmail.com',
					'hd'    => '',
					'sub'   => 'gmail-sub',
				]
			)
		);
		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( $user_id, $result->ID );
		$this->assertSame( 'gmail-sub', (string) get_user_meta( $user_id, Lean_Google_Login_Auth::META_SUB, true ) );
	}

	// -------------------------------------------------------------------------
	// Core account eligibility
	// -------------------------------------------------------------------------

	public function test_the_core_policy_filter_can_deny_a_disabled_account() {
		// Account-disable / 2FA plugins hook wp_authenticate_user; the plugin must
		// honour a veto there before issuing a session.
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		$deny = static function () {
			return new WP_Error( 'account_disabled', 'This account is disabled.' );
		};
		add_filter( 'wp_authenticate_user', $deny );
		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims() );
		remove_filter( 'wp_authenticate_user', $deny );

		$this->assertWPError( $result );
		$this->assertSame( 'account_disabled', $result->get_error_code() );
	}

	// -------------------------------------------------------------------------
	// Provisioning
	// -------------------------------------------------------------------------

	public function test_unknown_user_is_rejected_when_auto_create_is_off() {
		update_option( Lean_Google_Login_Auth::OPTION_AUTO_CREATE, '0' );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'email' => 'new@example.com' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_no_account', $result->get_error_code() );
	}

	public function test_unknown_user_is_created_with_the_default_role_when_auto_create_is_on() {
		update_option( Lean_Google_Login_Auth::OPTION_AUTO_CREATE, '1' );
		update_option( Lean_Google_Login_Auth::OPTION_DEFAULT_ROLE, 'editor' );

		$this->assertFalse( get_user_by( 'email', 'new@example.com' ) );

		$result = Lean_Google_Login_Auth::authenticate_claims(
			$this->claims(
				[
					'email' => 'new@example.com',
					'sub'   => 'new-sub',
				]
			)
		);

		$this->assertInstanceOf( 'WP_User', $result );
		$this->assertSame( 'new@example.com', $result->user_email );
		$this->assertContains( 'editor', $result->roles );
		$this->assertSame( 'new-sub', (string) get_user_meta( $result->ID, Lean_Google_Login_Auth::META_SUB, true ) );
	}

	public function test_auto_created_user_respects_the_domain_allow_list() {
		update_option( Lean_Google_Login_Auth::OPTION_AUTO_CREATE, '1' );
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, 'allowed.com' );

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims( [ 'email' => 'new@notallowed.com' ] ) );
		$this->assertWPError( $result );
		$this->assertSame( 'lean_google_login_domain', $result->get_error_code() );
		$this->assertFalse( get_user_by( 'email', 'new@notallowed.com' ) );
	}

	// -------------------------------------------------------------------------
	// Veto filter
	// -------------------------------------------------------------------------

	public function test_the_authenticated_user_filter_can_veto() {
		$this->factory->user->create( [ 'user_email' => 'alice@example.com' ] );

		add_filter(
			'lean_google_login_authenticated_user',
			static function () {
				return new WP_Error( 'blocked', 'Second factor required.' );
			}
		);

		$result = Lean_Google_Login_Auth::authenticate_claims( $this->claims() );
		remove_all_filters( 'lean_google_login_authenticated_user' );

		$this->assertWPError( $result );
		$this->assertSame( 'blocked', $result->get_error_code() );
	}

	// -------------------------------------------------------------------------
	// allowed_domains() parsing
	// -------------------------------------------------------------------------

	public function test_allowed_domains_parses_separators_and_strips_at() {
		update_option( Lean_Google_Login_Auth::OPTION_ALLOWED_DOMAINS, " Example.com,  @Foo.org\nexample.com " );
		$this->assertSame( [ 'example.com', 'foo.org' ], Lean_Google_Login_Auth::allowed_domains() );
	}
}
