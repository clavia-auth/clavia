<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Access\AccessContract;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use ClaviaTest\Support\AcceptanceTestCase;
use Mezzio\Router\RouteCollector;

/**
 * `docs/openapi/authorization-api.yaml` and the routes under `/access/v1` are the same set: an
 * endpoint is not added without its contract, and the contract describes nothing that is not served.
 */
final class AuthorizationApiCoverageTest extends AcceptanceTestCase
{
    public function testEveryRouteIsAnOperationAndEveryOperationARoute(): void
    {
        // The routes exist only while a decision engine is named.
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $described = array_map(
            static fn (Operation $operation): string => (string) $operation,
            $this->container()->get(AccessContract::class)->operations(),
        );

        $routed = [];
        foreach ($this->container()->get(RouteCollector::class)->getRoutes() as $route) {
            if (! str_starts_with($route->getPath(), '/access/')) {
                continue;
            }
            foreach ($route->getAllowedMethods() ?? [] as $method) {
                $routed[] = $method . ' ' . $route->getPath();
            }
        }

        self::assertNotSame([], $routed);
        self::assertEqualsCanonicalizing($routed, $described);
    }
}
