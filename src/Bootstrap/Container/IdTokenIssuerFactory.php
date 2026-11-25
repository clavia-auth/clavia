<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Oidc\ApplicationClaims;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Port\TokenSigner;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class IdTokenIssuerFactory
{
    public function __invoke(ContainerInterface $container): IdTokenIssuer
    {
        /** @var TokenSigner $signer */
        $signer = $container->get(TokenSigner::class);
        /** @var CompactJws $jws */
        $jws = $container->get(CompactJws::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $issuer = $settings->issuer();
        $lifetime = $settings->idTokenLifetime;
        assert($issuer !== '' && $lifetime > 0);

        /** @var ApplicationClaims $claims */
        $claims = $container->get(ApplicationClaims::class);

        return new IdTokenIssuer($signer, $jws, $issuer, $lifetime, $claims);
    }
}
