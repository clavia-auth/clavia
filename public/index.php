<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Mezzio\Application;
use Psr\Container\ContainerInterface;

// Every PHP warning and notice is a failure, whatever php.ini says: the pipeline
// turns them into errors rather than carrying on from half-built state.
error_reporting(E_ALL);

// …and none of it is ever printed into a response; it goes to the log.
ini_set('display_errors', '0');

chdir(dirname(__DIR__));

require 'vendor/autoload.php';

// Self-called so that nothing leaks into the global scope.
(static function (): void {
    /** @var ContainerInterface $container */
    $container = require 'config/container.php';

    /** @var Application $app */
    $app = $container->get(Application::class);

    (require 'config/pipeline.php')($app);
    (require 'config/routes.php')($app);

    $app->run();
})();
