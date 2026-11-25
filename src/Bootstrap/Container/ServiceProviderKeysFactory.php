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
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeys;
use Clavia\Adapter\Secondary\Saml\Remote\CertificateCache;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\SecretCipher;
use Clavia\Bootstrap\RemoteSigningKeys;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use LogicException;
use Psr\Container\ContainerInterface;

/**
 * The SAML service provider's keys, from `CLAVIA_SAML_KEY_BACKEND`: sealed in PostgreSQL, or named in
 * a KMS. Building them calls no provider: the first certificate or signature does.
 */
final class ServiceProviderKeysFactory
{
    public function __invoke(ContainerInterface $container): ServiceProviderKeys
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        if (! $settings->samlKeyBackend->isRemote()) {
            /** @var Database $database */
            $database = $container->get(Database::class);
            /** @var SecretCipher $cipher */
            $cipher = $container->get(SecretCipher::class);

            return new PostgresServiceProviderKeys($database, $cipher);
        }

        // The settings refuse a remote backend without both references, and a next half of a pair.
        $backend = $settings->samlKeyBackend->value;
        $signing = $settings->samlSigningKeyRef ?? throw new LogicException('Checked by the settings.');
        $encryption = $settings->samlEncryptionKeyRef ?? throw new LogicException('Checked by the settings.');
        $keys = new RemoteSigningKeys($container, $settings);
        /** @var CertificateCache $cache */
        $cache = $container->get(CertificateCache::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);

        return new RemoteServiceProviderKeys(
            $keys->keyFor($backend, $signing),
            $keys->decryptionKeyFor($backend, $encryption),
            $settings->samlNextSigningKeyRef === null
                ? null
                : $keys->keyFor($backend, $settings->samlNextSigningKeyRef),
            $settings->samlNextEncryptionKeyRef === null
                ? null
                : $keys->decryptionKeyFor($backend, $settings->samlNextEncryptionKeyRef),
            array_map(
                static fn (string $reference) => $keys->decryptionKeyFor($backend, $reference),
                $settings->samlRetiredEncryptionKeyRefs,
            ),
            $cache,
            $clock,
            $random,
            SamlServiceProviderHost::of($settings),
        );
    }
}
