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
use Clavia\Adapter\Secondary\Signing\Postgres\PostgresSigningKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Bootstrap\SigningBackend;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class SigningKeyStoreFactory
{
    public function __invoke(ContainerInterface $container): SigningKeyStore
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        SigningBackend::requirePostgres($settings);

        /** @var Database $database */
        $database = $container->get(Database::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);

        return new PostgresSigningKeyStore($database, $cipher);
    }
}
