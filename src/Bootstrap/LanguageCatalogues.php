<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Adapter\Secondary\Messages\IcuMessages;
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Language;

/**
 * Every language `CLAVIA_LANGUAGES` offers has a catalogue: checked when the settings load, so a
 * deployment offering a language it cannot show refuses to start (`bin/clavia` stops with 78), rather
 * than answering in the default language and logging it on every page.
 */
final class LanguageCatalogues
{
    /** The catalogues shipped with the server, one ARB file per language. */
    public const string DIRECTORY = __DIR__ . '/../../translations';

    private function __construct()
    {
    }

    /** @throws InvalidSettings */
    public static function check(Settings $settings, string $directory = self::DIRECTORY): void
    {
        foreach ($settings->languages as $tag) {
            if (! is_file(IcuMessages::path($directory, Language::fromString($tag)))) {
                throw new InvalidSettings(sprintf(
                    'CLAVIA_LANGUAGES offers %s, which has no catalogue (translations/%s.arb).',
                    $tag,
                    Language::fromString($tag)->tag,
                ));
            }
        }
    }
}
