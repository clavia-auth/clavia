<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Access\AccessApiMiddleware;
use Clavia\Adapter\Primary\Http\Access\AccessContract;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Authorization\Caller\AuthenticateAuthorizationCaller;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class AccessApiMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): AccessApiMiddleware
    {
        /** @var AccessContract $contract */
        $contract = $container->get(AccessContract::class);
        /** @var AuthenticateAuthorizationCaller $authenticate */
        $authenticate = $container->get(AuthenticateAuthorizationCaller::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new AccessApiMiddleware(
            $contract,
            $authenticate,
            // The protection space is this API: a token for any other audience is refused here.
            new BearerChallenger($settings->authorizationApiAudience()),
            $responder,
            // The origin a DPoP proof's `htu` names: this API's host, never the request's.
            'https://' . $settings->managementHost(),
        );
    }
}
