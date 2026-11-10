FROM wordpress:php8.3-apache

RUN apt-get update && \
	apt-get install -y --no-install-recommends less mariadb-client && \
	rm -r /var/lib/apt/lists/* && \
	a2enmod rewrite expires

# WP-CLI, for `docker compose exec wordpress wp ...` during development.
RUN curl -sS -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
	chmod +x /usr/local/bin/wp && \
	printf '#!/bin/sh\nexec wp --allow-root "$@"\n' > /usr/local/bin/wpc && \
	chmod +x /usr/local/bin/wpc

EXPOSE 80
