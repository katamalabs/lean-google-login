<?php
/**
 * Uninstall cleanup for Lean Sign in with Google.
 *
 * Removes the plugin's options, any leftover OAuth-state transients, and the
 * per-user Google account link meta.
 *
 * @package lean-sign-in-with-google
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$lean_sign_in_with_google_options = [
	'lean_sign_in_with_google_client_id',
	'lean_sign_in_with_google_client_secret',
	'lean_sign_in_with_google_allowed_domains',
	'lean_sign_in_with_google_auto_create',
	'lean_sign_in_with_google_default_role',
];

/**
 * Remove everything the plugin keeps in a site's own tables: its options, the
 * short-lived OAuth-state transients, and the Google-account link user meta.
 *
 * @param string[] $options Option names to delete.
 */
function lean_sign_in_with_google_uninstall_site( array $options ): void {
	global $wpdb;

	foreach ( $options as $option ) {
		delete_option( $option );
	}

	// OAuth-state transients are keyed by a hash, so they are removed by prefix.
	$transient_like = $wpdb->esc_like( '_transient_lgl_state_' ) . '%';
	$timeout_like   = $wpdb->esc_like( '_transient_timeout_lgl_state_' ) . '%';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $transient_like, $timeout_like ) );
}

if ( is_multisite() ) {
	foreach ( get_sites(
		[
			'fields' => 'ids',
			'number' => 0,
		]
	) as $lean_sign_in_with_google_blog_id ) {
		switch_to_blog( (int) $lean_sign_in_with_google_blog_id );
		lean_sign_in_with_google_uninstall_site( $lean_sign_in_with_google_options );
		restore_current_blog();
	}
} else {
	lean_sign_in_with_google_uninstall_site( $lean_sign_in_with_google_options );
}

// The Google-account link is user meta (global, one row per user), so remove it once.
delete_metadata( 'user', 0, 'lean_sign_in_with_google_sub', '', true );
