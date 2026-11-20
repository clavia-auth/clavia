<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Ui\Http\Shared\MethodNotAllowedMiddleware;
use Clavia\Ui\Http\Shared\NotFoundHandler;
use Laminas\Stratigility\Middleware\ErrorHandler;
use Mezzio\Application;
use Mezzio\Router\Middleware\DispatchMiddleware;
use Mezzio\Router\Middleware\ImplicitHeadMiddleware;
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

    $app->pipe(RouteMiddleware::class);
    // HEAD is answered wherever GET is, without a body (RFC 9110 §9.3.2). Nothing else
    // is implied: there is no automatic OPTIONS.
    $app->pipe(ImplicitHeadMiddleware::class);
    $app->pipe(MethodNotAllowedMiddleware::class);
    $app->pipe(DispatchMiddleware::class);

    $app->pipe(NotFoundHandler::class);
};
