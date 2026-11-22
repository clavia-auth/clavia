<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\AccessTokenMinter;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Port\TokenSigner;
use Clavia\Configuration\Settings;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class AccessTokenMinterFactory
{
    public function __invoke(ContainerInterface $container): AccessTokenMinter
    {
        /** @var AccessTokenRepository $tokens */
        $tokens = $container->get(AccessTokenRepository::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var TokenSigner $signer */
        $signer = $container->get(TokenSigner::class);
        /** @var CompactJws $jws */
        $jws = $container->get(CompactJws::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $issuer = $settings->issuer();
        assert($issuer !== '');

        return new AccessTokenMinter($tokens, $resourceServers, $signer, $jws, $secrets, $random, $issuer);
    }
}
