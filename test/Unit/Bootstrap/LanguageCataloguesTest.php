<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Bootstrap;

use Clavia\Bootstrap\LanguageCatalogues;
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use PHPUnit\Framework\TestCase;

/** A language without a catalogue refuses to start, rather than showing the default language everywhere. */
final class LanguageCataloguesTest extends TestCase
{
    private const array MINIMAL = ['CLAVIA_ROOT_DOMAIN' => 'acme.test'];

    public function testTheShippedLanguagesHaveTheirCatalogues(): void
    {
        $this->expectNotToPerformAssertions();

        LanguageCatalogues::check(Settings::fromEnvironment(self::MINIMAL));
    }

    public function testALanguageWithoutACatalogueIsRefused(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_LANGUAGES' => 'en de']);

        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains(
            'CLAVIA_LANGUAGES offers de, which has no catalogue (translations/de.arb).',
        );

        LanguageCatalogues::check($settings);
    }
}
