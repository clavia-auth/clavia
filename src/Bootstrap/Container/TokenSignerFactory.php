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
use Clavia\Adapter\Secondary\Signing\Postgres\PostgresTokenSigner;
use Clavia\Adapter\Secondary\Signing\Remote\PublicKeyCache;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteTokenSigner;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\TokenSigner;
use Clavia\Bootstrap\RemoteSigningKeys;
use Clavia\Bootstrap\SigningBackend;
use Clavia\Configuration\Settings;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

/**
 * The configured signing backend: `postgres`, or the remote key `CLAVIA_SIGNING_KEY_REF`
 * names with the retired keys still published beside it.
 */
final class TokenSignerFactory
{
    public function __invoke(ContainerInterface $container): TokenSigner
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        if (SigningBackend::managesItsKeys($settings)) {
            /** @var Database $database */
            $database = $container->get(Database::class);
            /** @var SecretCipher $cipher */
            $cipher = $container->get(SecretCipher::class);

            return new PostgresTokenSigner($database, $cipher, $clock);
        }

        // Settings refuse a remote backend without a key reference.
        assert($settings->signingKeyRef !== null);
        $keys = new RemoteSigningKeys($container, $settings);
        /** @var SigningAlgorithm $algorithm */
        $algorithm = $container->get(SigningAlgorithm::class);
        /** @var PublicKeyCache $cache */
        $cache = $container->get(PublicKeyCache::class);

        return new RemoteTokenSigner(
            $keys->key($settings->signingKeyRef),
            array_map($keys->key(...), $settings->signingRetiredKeyRefs),
            $algorithm,
            $cache,
        );
    }
}
