COMMIT := $(shell git rev-parse --short=8 HEAD)
BASENAME := $(shell basename $(CURDIR))
# WordPress.org plugin slug. Decoupled from the repo/directory name so the
# distributed package folder is the reserved slug regardless of the checkout dir.
SLUG := $(or $(SLUG),lean-sign-in-with-google)
ZIP_FILENAME := $(or $(ZIP_FILENAME),$(SLUG).zip)
BUILD_DIR := $(or $(BUILD_DIR),build)
VENDOR_AUTOLOAD := vendor/autoload.php

ifeq ($(PROD)x, x)
	COMPOSER_ARGS := --prefer-dist --no-progress
else
	COMPOSER_ARGS := --no-dev
endif

help:  ## Print the help documentation
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build:  ## Build the release zip (always rebuilt from the current HEAD commit)
	mkdir -p $(BUILD_DIR)
	git archive --format=zip --worktree-attributes --prefix=$(SLUG)/ --output=$(BUILD_DIR)/$(ZIP_FILENAME) $(COMMIT)

.PHONY: clean
clean:  ## clean
	rm -rf build

$(VENDOR_AUTOLOAD):
	composer install $(COMPOSER_ARGS)

.PHONY: composer
composer: $(VENDOR_AUTOLOAD) ## Runs composer install

.PHONY: lint
lint: composer ## PHP Lint
	vendor/squizlabs/php_codesniffer/bin/phpcs

.PHONY: fmt
fmt: composer ## PHP Fmt
	vendor/squizlabs/php_codesniffer/bin/phpcbf

.PHONY: dev
dev:  ## Docker up
	docker compose up

.PHONY: bash
bash:  ## Runs bash shell in wordpress container
	docker exec -it -w /var/www/html $(BASENAME)-wordpress-1 bash

.PHONY: test
test:  ## Run tests in Docker (builds fresh each time)
	@trap 'docker compose -f docker-compose.test.yml down' EXIT; \
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test

.PHONY: test-clean
test-clean:  ## Remove test containers and images
	docker compose -f docker-compose.test.yml down --rmi local --volumes
