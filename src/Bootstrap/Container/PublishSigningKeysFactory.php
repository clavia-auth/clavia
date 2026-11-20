<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Application\Port\TokenSigner;
use Psr\Container\ContainerInterface;

final class PublishSigningKeysFactory
{
    public function __invoke(ContainerInterface $container): PublishSigningKeys
    {
        /** @var TokenSigner $signer */
        $signer = $container->get(TokenSigner::class);

        return new PublishSigningKeys($signer);
    }
}
