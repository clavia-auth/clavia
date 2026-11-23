<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ManagementApiMiddleware;
use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ManagementApiMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): ManagementApiMiddleware
    {
        /** @var ManagementContract $contract */
        $contract = $container->get(ManagementContract::class);
        /** @var AuthenticateManagementCaller $authenticate */
        $authenticate = $container->get(AuthenticateManagementCaller::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);

        return new ManagementApiMiddleware(
            $contract,
            $authenticate,
            // The protection space is this API, not the issuer: a token for any other
            // audience is refused here.
            new BearerChallenger($settings->managementApiAudience()),
            $responder,
            $audit,
            // The origin a DPoP proof's `htu` names: this API's host, never the request's.
            'https://' . $settings->managementHost(),
        );
    }
}
