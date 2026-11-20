<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Ui\Http\Shared\HealthHandler;
use Mezzio\Application;

/**
 * Every route the server answers. One process serves all four surfaces; which host
 * reaches which paths is the reverse proxy's decision (see the Caddyfile).
 */
return static function (Application $app): void {
    $app->get('/healthz', HealthHandler::class, 'ops.healthz');
};
