<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\AuthorizationServerContract;
use Mezzio\Router\RouteCollector;

/**
 * The authorization server's document and its routes name the same operations (#93): an endpoint
 * cannot be added undocumented, and the document cannot describe one that is not there.
 */
final class AuthorizationServerCoverageTest extends AcceptanceTestCase
{
    public function testEveryRouteIsAnOperationAndEveryOperationARoute(): void
    {
        // Every route there can be: registration's exist only when it is on.
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $described = array_map(
            static fn (Operation $operation): string => (string) $operation,
            AuthorizationServerContract::document()->operations(),
        );

        $routed = [];
        foreach ($this->container()->get(RouteCollector::class)->getRoutes() as $route) {
            if (preg_match('#^/(oauth2|oidc|\.well-known)/#', $route->getPath()) !== 1) {
                continue;
            }
            foreach ($route->getAllowedMethods() ?? [] as $method) {
                $routed[] = $method . ' ' . $route->getPath();
            }
        }

        self::assertEqualsCanonicalizing($routed, $described);
    }
}
