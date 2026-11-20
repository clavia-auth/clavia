# PHP-FPM for local development. Caddy (docker-compose.yml) terminates TLS and speaks
# FastCGI to this container on :9000; the project is bind-mounted at /app.
FROM php:8.5-fpm-alpine

# pdo_pgsql/pgsql: PostgreSQL. redis: sessions and the other short-TTL material.
# intl: IDN and locale-aware handling. OPcache is part of PHP itself since 8.5.
COPY --from=mlocati/php-extension-installer:latest /usr/bin/install-php-extensions /usr/local/bin/
RUN install-php-extensions pdo_pgsql pgsql redis intl

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

COPY php.ini /usr/local/etc/php/conf.d/zz-clavia.ini
COPY fpm.conf /usr/local/etc/php-fpm.d/zz-clavia.conf

WORKDIR /app
