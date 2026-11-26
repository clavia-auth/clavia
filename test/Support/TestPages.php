<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Primary\Http\Shared\LanguageChoice;
use Clavia\Adapter\Primary\Http\Shared\PageLanguage;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Adapter\Secondary\Messages\IcuMessages;
use Clavia\Bootstrap\LanguageCatalogues;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use Mezzio\Template\TemplateRendererInterface;
use Psr\Log\NullLogger;

/** A {@see PageRenderer} over other templates, with the shipped catalogues, for tests that replace the templates. */
final class TestPages
{
    private function __construct()
    {
    }

    public static function renderer(TemplateRendererInterface $templates): PageRenderer
    {
        $languages = Languages::of(
            [Language::fromString('en'), Language::fromString('fr')],
            Language::fromString('en'),
        );

        return new PageRenderer(
            $templates,
            new LanguageChoice($languages),
            new PageLanguage(),
            new IcuMessages(LanguageCatalogues::DIRECTORY, $languages, new NullLogger()),
        );
    }
}
