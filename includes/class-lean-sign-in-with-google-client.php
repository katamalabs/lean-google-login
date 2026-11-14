<?php
/**
 * The Google OAuth2 client: builds the consent URL, exchanges the returned
 * authorization code for tokens, and reads the identity claims out of the
 * id_token.
 *
 * Structurally a trimmed twin of Lean SMTP's Gmail OAuth transport, minus
 * everything send- and refresh-token related. Login needs only the
 * non-sensitive `openid email profile` scopes, which — unlike Gmail's
 * restricted `gmail.send` — require no Google app verification and work with an
 * External or Internal consent screen, consumer or Workspace. Login is a
 * one-shot: exchange the code, read the identity, discard the tokens. Nothing
 * is stored here except (elsewhere) the client id and secret.
 *
 * `authorize_url()` and `claims_from_id_token()` are pure and deterministic, so
 * the consent round-trip is unit-tested without a browser or a network call.
 *
 * @package lean-sign-in-with-google
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Lean_Sign_In_With_Google_Client {

	const OPTION_CLIENT_ID     = 'lean_sign_in_with_google_client_id';
	const OPTION_CLIENT_SECRET = 'lean_sign_in_with_google_client_secret';

	// Non-sensitive scopes only: identity, nothing else. `openid email` give the
	// verified address and the stable `sub`; `profile` gives the display name.
	const SCOPE     = 'openid email profile';
	const AUTH_URI  = 'https://accounts.google.com/o/oauth2/v2/auth';
	const TOKEN_URI = 'https://oauth2.googleapis.com/token';

	// admin-post action Google is pointed back at; also the registered redirect URI.
	const CALLBACK_ACTION = 'lean_sign_in_with_google_callback';

	// -------------------------------------------------------------------------
	// Configuration
	// -------------------------------------------------------------------------

	public static function client_id(): string {
		return Lean_Sign_In_With_Google_Config::get_string( self::OPTION_CLIENT_ID );
	}

	public static function client_secret(): string {
		return Lean_Sign_In_With_Google_Config::get_secret( self::OPTION_CLIENT_SECRET );
	}

	/** Whether the plugin has an OAuth client to authenticate against. */
	public static function is_configured(): bool {
		return '' !== self::client_id() && '' !== self::client_secret();
	}

	/**
	 * The redirect URI Google sends the browser back to after consent. Must be
	 * registered verbatim in the Google Cloud Console; the settings page prints
	 * it read-only for exactly that reason. admin-post.php is reachable while
	 * logged out, and the callback is registered for both priv and nopriv.
	 */
	public static function redirect_uri(): string {
		return admin_url( 'admin-post.php?action=' . self::CALLBACK_ACTION );
	}

	// -------------------------------------------------------------------------
	// Consent round-trip
	// -------------------------------------------------------------------------

	/**
	 * The Google consent URL to send the browser to. Pure and deterministic
	 * given its inputs, so it is unit-tested without a network.
	 *
	 * `access_type=online` and no `prompt=consent`: login is a one-shot, so no
	 * refresh token is wanted. `prompt=select_account` lets someone signed into
	 * several Google accounts pick which one to use. `$hd`, when given, is a
	 * Workspace-domain hint that pre-filters the account chooser — a UX nicety
	 * only; the real domain enforcement happens server-side against the claims.
	 *
	 * @param string $redirect_uri The registered redirect URI.
	 * @param string $state        An opaque anti-CSRF token echoed back to us.
	 * @param string $hd           Optional single Workspace domain hint.
	 */
	public static function authorize_url( string $redirect_uri, string $state, string $hd = '' ): string {
		$params = [
			'client_id'     => self::client_id(),
			'redirect_uri'  => $redirect_uri,
			'response_type' => 'code',
			'scope'         => self::SCOPE,
			'access_type'   => 'online',
			'prompt'        => 'select_account',
			'state'         => $state,
		];

		if ( '' !== $hd ) {
			$params['hd'] = $hd;
		}

		return self::AUTH_URI . '?' . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );
	}

	/**
	 * Read the identity claims out of a Google id_token (a JWT). The token came
	 * straight from Google's TLS token endpoint during the code exchange, so the
	 * signature is not re-verified here — only the payload is decoded. Pure;
	 * unit-tested.
	 *
	 * This trust assumption holds ONLY for an id_token obtained from the
	 * authorization-code exchange below. A token arriving by any other path
	 * (e.g. posted from a browser, as a One Tap flow would) would need full
	 * signature / aud / iss / exp verification — which is one reason this plugin
	 * ships only the server-side redirect flow.
	 *
	 * @return array<string, mixed> The decoded claims, or [] if unreadable.
	 */
	public static function claims_from_id_token( string $id_token ): array {
		$parts = explode( '.', $id_token );
		if ( count( $parts ) < 2 ) {
			return [];
		}

		$payload = $parts[1];
		$pad     = strlen( $payload ) % 4;
		if ( 0 !== $pad ) {
			$payload .= str_repeat( '=', 4 - $pad );
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a JWT payload segment returned by Google, not obfuscation.
		$json = base64_decode( strtr( $payload, '-_', '+/' ), true );
		if ( false === $json ) {
			return [];
		}

		$claims = json_decode( $json, true );
		return is_array( $claims ) ? $claims : [];
	}

	/**
	 * Exchange the authorization code Google returned for tokens, and return the
	 * identity claims read from the id_token. Called from the callback handler
	 * after the state has been verified. Stores nothing.
	 *
	 * @param string $code         The one-time authorization code.
	 * @param string $redirect_uri The same redirect URI used in the auth request.
	 * @return array<string, mixed>|WP_Error The id_token claims, or an error.
	 */
	public static function exchange_code( string $code, string $redirect_uri ) {
		$response = wp_remote_post(
			self::TOKEN_URI,
			[
				'timeout' => 15,
				'body'    => [
					'grant_type'    => 'authorization_code',
					'code'          => $code,
					'client_id'     => self::client_id(),
					'client_secret' => self::client_secret(),
					'redirect_uri'  => $redirect_uri,
				],
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$http = (int) wp_remote_retrieve_response_code( $response );
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( $http < 200 || $http >= 300 || ! is_array( $body ) || empty( $body['id_token'] ) ) {
			$message = is_array( $body ) && ! empty( $body['error_description'] )
				? (string) $body['error_description']
				: wp_remote_retrieve_response_message( $response );
			/* translators: 1: HTTP status code, 2: Google error message. */
			return new WP_Error( 'lean_sign_in_with_google_exchange_http_' . $http, sprintf( __( 'Google refused the sign-in (HTTP %1$d): %2$s', 'lean-sign-in-with-google' ), $http, $message ) );
		}

		$claims = self::claims_from_id_token( (string) $body['id_token'] );
		if ( empty( $claims ) ) {
			return new WP_Error( 'lean_sign_in_with_google_no_claims', __( 'Google returned a sign-in token that could not be read.', 'lean-sign-in-with-google' ) );
		}

		return $claims;
	}
}
