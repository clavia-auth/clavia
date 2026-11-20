<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Ui\Http\OAuth2\AuthorizeHandler;
use Clavia\Ui\Http\OAuth2\TokenHandler;
use Clavia\Ui\Http\Shared\HealthHandler;
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
};
