<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class ClientAuthenticatorFactory
{
    public function __invoke(ContainerInterface $container): ClientAuthenticator
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);

        return new ClientAuthenticator($clients, $hasher);
    }
}
