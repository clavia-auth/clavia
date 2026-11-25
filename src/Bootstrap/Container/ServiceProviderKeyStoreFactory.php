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
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class ServiceProviderKeyStoreFactory
{
    public function __invoke(ContainerInterface $container): ServiceProviderKeyStore
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        if ($settings->samlKeyBackend->isRemote()) {
            // An operator who put the keys in a KMS must never end up with keys in PostgreSQL unawares.
            throw new InvalidSettings(sprintf(
                "CLAVIA_SAML_KEY_BACKEND='%s' keeps the keys at the provider: create and rotate them there, and "
                . 'name them with the CLAVIA_SAML_*_KEY_REF settings.',
                $settings->samlKeyBackend->value,
            ));
        }
        /** @var Database $database */
        $database = $container->get(Database::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);

        return new PostgresServiceProviderKeyStore($database, $cipher, $random, SamlServiceProviderHost::of($settings));
    }
}
