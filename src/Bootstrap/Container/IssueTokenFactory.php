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
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\IssueToken;
use Psr\Container\ContainerInterface;

final class IssueTokenFactory
{
    public function __invoke(ContainerInterface $container): IssueToken
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var AuthorizationCodeGrant $authorizationCode */
        $authorizationCode = $container->get(AuthorizationCodeGrant::class);

        // Every grant the token endpoint offers. A grant not listed here does not exist.
        return new IssueToken($authenticator, $authorizationCode);
    }
}
