<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeyStore;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class ServiceProviderKeyStoreFactory
{
    public function __invoke(ContainerInterface $container): ServiceProviderKeyStore
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var Database $database */
        $database = $container->get(Database::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);

        // `postgres` is the only backend yet; a KMS one has no store (docs/design/saml-connections.md §3).
        $host = parse_url($settings->issuerUrl, PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            throw new \LogicException('The issuer has no host.');
        }

        return new PostgresServiceProviderKeyStore($database, $cipher, $random, $host);
    }
}
