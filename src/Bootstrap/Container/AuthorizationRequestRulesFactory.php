<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Authorize\AuthorizationRequestRules;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class AuthorizationRequestRulesFactory
{
    public function __invoke(ContainerInterface $container): AuthorizationRequestRules
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var NonceRegistry $nonces */
        $nonces = $container->get(NonceRegistry::class);
        /** @var ReadRequestedAccess $requestedAccess */
        $requestedAccess = $container->get(ReadRequestedAccess::class);

        return new AuthorizationRequestRules($clients, $nonces, $requestedAccess);
    }
}
