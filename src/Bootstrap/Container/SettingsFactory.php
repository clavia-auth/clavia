<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Bootstrap\EnvironmentVariables;
use Clavia\Bootstrap\LanguageCatalogues;
use Clavia\Bootstrap\SamlKeyReferences;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

/**
 * Builds the {@see Settings} once per process from the environment and `.env`.
 */
final class SettingsFactory
{
    public function __invoke(ContainerInterface $container): Settings
    {
        /** @var array{clavia: array{project_root: string}} $config */
        $config = $container->get('config');

        $settings = Settings::fromEnvironment(EnvironmentVariables::load($config['clavia']['project_root']));
        SamlKeyReferences::check($settings);
        LanguageCatalogues::check($settings);

        return $settings;
    }
}
