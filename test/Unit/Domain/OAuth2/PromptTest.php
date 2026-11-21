<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Prompt;
use PHPUnit\Framework\TestCase;

final class PromptTest extends TestCase
{
    public function testNoPromptAsksForNothing(): void
    {
        $prompt = Prompt::fromParameter(null);

        self::assertFalse($prompt->forbidsInteraction());
        self::assertFalse($prompt->demandsConsent());
        self::assertNull($prompt->without(Prompt::CONSENT));
    }

    public function testValuesAreSpaceSeparatedAndCaseSensitive(): void
    {
        self::assertTrue(Prompt::fromParameter('login consent')->demandsConsent());
        self::assertFalse(Prompt::fromParameter('Consent')->demandsConsent());
        self::assertTrue(Prompt::fromParameter('none')->forbidsInteraction());
        self::assertTrue(Prompt::fromParameter('  none  ')->forbidsInteraction());
    }

    public function testNoneWithAnythingElseIsAContradiction(): void
    {
        try {
            Prompt::fromParameter('none consent');
            self::fail('A contradiction was accepted.');
        } catch (OAuth2Error $error) {
            self::assertSame(ErrorCode::InvalidRequest, $error->error);
        }
    }

    public function testTakingAValueOutKeepsTheRestInOrder(): void
    {
        $prompt = Prompt::fromParameter('login consent select_account');

        self::assertSame('login select_account', $prompt->without('consent'));
        self::assertNull(Prompt::fromParameter('consent consent')->without('consent'));
        self::assertSame('login', Prompt::fromParameter('login')->without('consent'));
    }
}
