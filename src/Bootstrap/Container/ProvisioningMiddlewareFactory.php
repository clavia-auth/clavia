<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Scim\ProvisioningMiddleware;
use Clavia\Adapter\Primary\Http\Scim\ScimResponder;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Provisioning\AuthenticateProvisioningToken;
use Psr\Container\ContainerInterface;

final class ProvisioningMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): ProvisioningMiddleware
    {
        /** @var AuthenticateProvisioningToken $authenticate */
        $authenticate = $container->get(AuthenticateProvisioningToken::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var ScimResponder $responder */
        $responder = $container->get(ScimResponder::class);

        return new ProvisioningMiddleware($authenticate, $audit, $responder);
    }
}
