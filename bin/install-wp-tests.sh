#!/usr/bin/env bash
#
# Download WordPress core and create the test database.
# The test library itself comes from the wp-phpunit/wp-phpunit composer package.
#
set -euo pipefail

if [ $# -lt 3 ]; then
	echo "usage: $0 <db-name> <db-user> <db-pass> [db-host] [wp-version]"
	exit 1
fi

DB_NAME=$1
DB_USER=$2
DB_PASS=$3
DB_HOST=${4-localhost}
WP_VERSION=${5-latest}

TMPDIR=${TMPDIR-/tmp}
TMPDIR=$(echo "$TMPDIR" | sed -e "s/\/$//")
WP_CORE_DIR=${WP_CORE_DIR-$TMPDIR/wordpress}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -nv -O "$2" "$1"
	else
		echo "error: neither curl nor wget is available to download $1" >&2
		return 1
	fi
}

# The WordPress version recorded in an already-extracted core, or empty.
installed_wp_version() {
	local version_file="$WP_CORE_DIR/wp-includes/version.php"
	[ -f "$version_file" ] || return 0
	sed -n "s/^\$wp_version = '\([^']*\)'.*/\1/p" "$version_file" | head -1
}

# ── Download WordPress core ──────────────────────────────────────────────────

install_wp() {
	mkdir -p "$WP_CORE_DIR"

	if [ -d "$WP_CORE_DIR/wp-includes" ]; then
		local current
		current=$(installed_wp_version)
		if [ "$WP_VERSION" = 'latest' ]; then
			echo "WordPress core already present (version ${current:-unknown}); keeping it for 'latest'."
			return
		fi
		if [ "$current" = "$WP_VERSION" ]; then
			echo "WordPress ${WP_VERSION} already present at $WP_CORE_DIR, skipping download."
			return
		fi
		echo "Installed WordPress (${current:-unknown}) does not match requested ${WP_VERSION}; reinstalling."
		rm -rf "${WP_CORE_DIR:?}/"*
	fi

	echo "Downloading WordPress ${WP_VERSION}..."

	local archive_name
	if [ "$WP_VERSION" = 'latest' ]; then
		archive_name='latest'
	else
		archive_name="wordpress-$WP_VERSION"
	fi

	download "https://wordpress.org/${archive_name}.tar.gz" "$TMPDIR/wordpress.tar.gz"
	tar --strip-components=1 -zxmf "$TMPDIR/wordpress.tar.gz" -C "$WP_CORE_DIR"

	if [ ! -f "$WP_CORE_DIR/wp-includes/version.php" ]; then
		echo "error: WordPress core did not extract correctly into $WP_CORE_DIR" >&2
		return 1
	fi

	if [ "$WP_VERSION" != 'latest' ]; then
		local extracted
		extracted=$(installed_wp_version)
		if [ "$extracted" != "$WP_VERSION" ]; then
			echo "error: downloaded WordPress ${extracted:-unknown} does not match requested ${WP_VERSION}." >&2
			return 1
		fi
	fi
}

# ── Create the test database ─────────────────────────────────────────────────

install_db() {
	# Split "host", "host:port" or "host:/path/to/socket" without word-splitting.
	local DB_HOSTNAME=${DB_HOST%%:*}
	local DB_SOCK_OR_PORT=${DB_HOST#*:}
	[ "$DB_SOCK_OR_PORT" = "$DB_HOST" ] && DB_SOCK_OR_PORT=""

	local EXTRA=()
	if [ -n "$DB_HOSTNAME" ]; then
		if [[ "$DB_SOCK_OR_PORT" =~ ^[0-9]+$ ]]; then
			EXTRA=(--host="$DB_HOSTNAME" --port="$DB_SOCK_OR_PORT" --protocol=tcp)
		elif [ -n "$DB_SOCK_OR_PORT" ]; then
			EXTRA=(--socket="$DB_SOCK_OR_PORT")
		else
			EXTRA=(--host="$DB_HOSTNAME" --protocol=tcp)
		fi
	fi

	echo "Creating database ${DB_NAME} (if it doesn't exist)..."
	# A pre-existing database is fine; any other failure is not fatal to the run.
	mysqladmin create "$DB_NAME" --user="$DB_USER" --password="$DB_PASS" "${EXTRA[@]}" 2>/dev/null \
		|| echo "Database ${DB_NAME} already exists or could not be created; continuing."
}

install_wp
install_db
