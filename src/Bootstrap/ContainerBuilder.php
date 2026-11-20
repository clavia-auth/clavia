<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Laminas\ServiceManager\ServiceManager;

/**
 * Builds the dependency-injection container from the merged configuration.
 *
 * @psalm-import-type ServiceManagerConfiguration from ServiceManager
 */
final class ContainerBuilder
{
    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $config The merged configuration (see `config/config.php`); its
     *                                     `dependencies` key describes the services, and the whole
     *                                     array is itself published as the `config` service.
     */
    public static function build(array $config): ServiceManager
    {
        /** @psalm-var ServiceManagerConfiguration $dependencies */
        $dependencies = $config['dependencies'] ?? [];
        $dependencies['services'] = ['config' => $config] + ($dependencies['services'] ?? []);

        return new ServiceManager($dependencies);
    }
}
