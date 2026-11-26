<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use Psr\Container\ContainerInterface;

/** The languages `CLAVIA_LANGUAGES` offers, and `CLAVIA_DEFAULT_LANGUAGE`: checked when the settings loaded. */
final class LanguagesFactory
{
    public function __invoke(ContainerInterface $container): Languages
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return Languages::of(
            array_map(static fn (string $tag): Language => Language::fromString($tag), $settings->languages),
            Language::fromString($settings->defaultLanguage),
        );
    }
}
