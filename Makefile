# Development shortcuts. The application and its tooling run in the `php` container,
# so nothing but Docker is needed on the host. Start with:
#
#   cp .env.example .env    # set CLAVIA_ROOT_DOMAIN
#   ./setup-ssl.sh          # mkcert certificate for *.{CLAVIA_ROOT_DOMAIN}
#   make up install migrate seed

PHP := docker compose exec php

.PHONY: up down install config migrate db-status seed authorize-url check test lint analyse arch shell e2e-up e2e-verify e2e-down

# Caddy, PHP-FPM, PostgreSQL (dev + test) and Redis.
up:
	docker compose up -d --build

down:
	docker compose down

install:
	$(PHP) composer install

# Print every CLAVIA_* setting as the server sees it.
config:
	$(PHP) bin/clavia config

# Apply the pending migrations of migrations/ to the development database.
migrate:
	$(PHP) bin/clavia db:migrate

# List the migrations and whether each is applied.
db-status:
	$(PHP) bin/clavia db:status

# Development data: a user, clients, the Management API, a signing key and the dashboard
# client. Safe to run again; refuses outside CLAVIA_ENVIRONMENT=development.
seed:
	$(PHP) bin/clavia seed-dev

# An authorization URL with a fresh PKCE pair, and the curl command that redeems the code.
authorize-url:
	$(PHP) bin/clavia authorize-url

# Everything a change must pass: coding standard, static analysis, the hexagonal
# dependency rules, the test suite.
check:
	$(PHP) composer check

test:
	$(PHP) composer test

lint:
	$(PHP) composer cs-check

analyse:
	$(PHP) composer static-analysis

arch:
	$(PHP) composer arch

shell:
	$(PHP) sh

# Clavia as it is deployed, for the end-to-end suites (test/e2e, docs/design/end-to-end-scenarios.md):
# the production topology on ports 80 and 443 of 127.0.0.1, so stop `make up` first. Needs mkcert.
e2e-up:
	test/e2e/up.sh

e2e-verify:
	test/e2e/verify.sh

e2e-down:
	test/e2e/down.sh
