<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Adapter\Primary\Http\Auth\LoginHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginPageHandler;
use Clavia\Adapter\Primary\Http\Auth\LogoutHandler;
use Clavia\Adapter\Primary\Http\Auth\ThemeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\TokenHandler;
use Clavia\Adapter\Primary\Http\Shared\HealthHandler;
use Mezzio\Application;

/**
 * Every route the server answers. One process serves all four surfaces; which host
 * reaches which paths is the reverse proxy's decision (see the Caddyfile).
 */
return static function (Application $app): void {
    $app->get('/healthz', HealthHandler::class, 'ops.healthz');

    // ── /oauth2/* — the authorization server. Callers authenticate as clients. ──
    $app->route('/oauth2/authorize', AuthorizeHandler::class, ['GET', 'POST'], 'oauth2.authorize');
    $app->post('/oauth2/token', TokenHandler::class, 'oauth2.token');

    // ── /auth/* — the interactive sign-in. The browser authenticates with its session
    // cookie; every state change is a POST, and logout has no GET on purpose. ──
    $app->get('/auth/login', LoginPageHandler::class, 'auth.login');
    $app->post('/auth/login', LoginHandler::class, 'auth.login.submit');
    $app->post('/auth/logout', LogoutHandler::class, 'auth.logout');
    $app->post('/auth/theme', ThemeHandler::class, 'auth.theme');
};
