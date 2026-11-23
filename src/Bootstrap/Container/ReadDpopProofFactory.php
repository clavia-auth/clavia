<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisDpopNonces;
use Clavia\Adapter\Secondary\Redis\RedisDpopReplayCache;
use Clavia\Adapter\Secondary\Signing\Jose\JoseDpopProofVerifier;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

/**
 * The DPoP proof reader on its adapters: `web-token/jwt-library` for the signature, Redis for the
 * replay cache and the nonces.
 */
final class ReadDpopProofFactory
{
    public function __invoke(ContainerInterface $container): ReadDpopProof
    {
        /** @var RedisConnection $redis */
        $redis = $container->get(RedisConnection::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->dpopProofLifetime;
        $window = $settings->dpopNonceLifetime;
        assert($lifetime > 0 && $window > 0);

        return new ReadDpopProof(
            new JoseDpopProofVerifier(),
            new RedisDpopReplayCache($redis),
            new RedisDpopNonces($redis, $secrets, $clock, $window),
            $clock,
            $lifetime,
        );
    }
}
