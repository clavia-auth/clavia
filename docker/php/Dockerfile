# PHP-FPM for Clavia, in two flavours of one image.
#
#   development  (the default, what docker-compose.yml builds): Caddy terminates TLS and speaks
#                FastCGI to this container on :9000; the project is bind-mounted at /app, with
#                Composer and the dev tooling.
#   production   (what a release publishes as ghcr.io/clavia-auth/clavia): the application is in
#                the image, with its runtime dependencies only. Built with the repository as a
#                named build context:
#
#                  docker buildx build docker/php --target production --build-context app=.
#
#                It is PHP-FPM alone, as in development: put Caddy, or any FastCGI-speaking
#                proxy, in front, and give it `public/` at the same path (`/app/public`).
#
# `development` comes last on purpose: a build with no --target ends there.

FROM php:8.5-fpm-alpine AS base

# pdo_pgsql/pgsql: PostgreSQL. redis: sessions and the other short-TTL material.
# intl: IDN and locale-aware handling. OPcache is part of PHP itself since 8.5.
# bcmath: simplesamlphp/xml-common, under the SAML service provider (arbitrary-precision integers).
COPY --from=mlocati/php-extension-installer:latest /usr/bin/install-php-extensions /usr/local/bin/
RUN install-php-extensions pdo_pgsql pgsql redis intl bcmath

COPY php.ini /usr/local/etc/php/conf.d/zz-clavia.ini
COPY fpm.conf /usr/local/etc/php-fpm.d/zz-clavia.conf

WORKDIR /app

# ── The application's runtime dependencies, with an authoritative classmap ───────────────────
FROM base AS vendor
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
COPY --from=app composer.json composer.lock ./
COPY --from=app src ./src
RUN composer install --no-dev --no-scripts --no-interaction --no-progress --prefer-dist \
        --classmap-authoritative

# ── production ───────────────────────────────────────────────────────────────────────────────
FROM base AS production
COPY production.ini /usr/local/etc/php/conf.d/zz-clavia-production.ini
COPY --from=vendor /app/vendor ./vendor
COPY --from=app composer.json ./composer.json
COPY --from=app bin ./bin
COPY --from=app config ./config
COPY --from=app migrations ./migrations
COPY --from=app public ./public
COPY --from=app src ./src
COPY --from=app templates ./templates
COPY --from=app docs/openapi ./docs/openapi

# ── development ──────────────────────────────────────────────────────────────────────────────
FROM base AS development
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
