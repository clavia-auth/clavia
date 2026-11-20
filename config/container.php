<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Bootstrap\ContainerBuilder;

/** @var array<string, mixed> $config */
$config = require __DIR__ . '/config.php';

return ContainerBuilder::build($config);
