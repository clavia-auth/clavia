<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Adapter\Primary\Http\Shared\AuditContextMiddleware;
use Clavia\Adapter\Primary\Http\Shared\MethodNotAllowedMiddleware;
use Clavia\Adapter\Primary\Http\Shared\NotFoundHandler;
use Laminas\Stratigility\Middleware\ErrorHandler;
use Mezzio\Application;
use Mezzio\Router\Middleware\DispatchMiddleware;
use Mezzio\Router\Middleware\RouteMiddleware;

/**
 * The middleware every request crosses, outermost first.
 *
 * Authentication is not here: each of the four surfaces (/oauth2, /oidc, /auth,
 * /api/v1) authenticates its callers differently, so that middleware is attached per
 * route in routes.php — never globally.
 */
return static function (Application $app): void {
    // Catches everything below it; the response never describes the error.
    $app->pipe(ErrorHandler::class);

    // Where the request came from, for every audit event it records.
    $app->pipe(AuditContextMiddleware::class);

    $app->pipe(RouteMiddleware::class);
    $app->pipe(MethodNotAllowedMiddleware::class);
    $app->pipe(DispatchMiddleware::class);

    $app->pipe(NotFoundHandler::class);
};
