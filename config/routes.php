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
use Clavia\Adapter\Primary\Http\Oidc\DiscoveryHandler;
use Clavia\Adapter\Primary\Http\Oidc\JwksHandler;
use Clavia\Adapter\Primary\Http\Oidc\UserInfoHandler;
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

    // ── /.well-known/* — the provider's metadata, public and cacheable. One document at
    // both locations: OpenID relying parties and RFC 8414 clients look in different places. ──
    $app->get('/.well-known/openid-configuration', DiscoveryHandler::class, 'oidc.discovery');
    $app->get('/.well-known/oauth-authorization-server', DiscoveryHandler::class, 'oauth2.metadata');

    // ── /oidc/* — OpenID Connect. The JWKS is public; userinfo takes a bearer access
    // token, on GET and POST (OIDC Core §5.3.1). ──
    $app->get('/oidc/jwks.json', JwksHandler::class, 'oidc.jwks');
    $app->route('/oidc/userinfo', UserInfoHandler::class, ['GET', 'POST'], 'oidc.userinfo');

    // ── /auth/* — the interactive sign-in. The browser authenticates with its session
    // cookie; every state change is a POST, and logout has no GET on purpose. ──
    $app->get('/auth/login', LoginPageHandler::class, 'auth.login');
    $app->post('/auth/login', LoginHandler::class, 'auth.login.submit');
    $app->post('/auth/logout', LogoutHandler::class, 'auth.logout');
    $app->post('/auth/theme', ThemeHandler::class, 'auth.theme');
};
