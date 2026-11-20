<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class SecretGeneratorTest extends TestCase
{
    public function testATokenIsFortyThreeUrlSafeCharacters(): void
    {
        $generator = new SecretGenerator(new SeededRandomSource());

        for ($i = 0; $i < 200; $i++) {
            // 32 bytes in base64url without padding: no '+', '/', or '='.
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $generator->token());
        }
    }

    public function testATokenCarriesThirtyTwoBytesOfEntropy(): void
    {
        $token = new SecretGenerator(new SeededRandomSource(7))->token();
        $expected = new SeededRandomSource(7)->bytes(32);

        self::assertSame($expected, base64_decode(strtr($token, '-_', '+/'), true));
    }

    public function testTokensDoNotRepeat(): void
    {
        $generator = new SecretGenerator(new SeededRandomSource());
        $tokens = array_map(static fn (int $_): string => $generator->token(), range(1, 500));

        self::assertCount(500, array_unique($tokens));
    }

    public function testAnAlphanumericValueHasTheRequestedLengthAndOnlyLettersAndDigits(): void
    {
        $generator = new SecretGenerator(new SeededRandomSource());

        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{32}$/', $generator->alphanumeric(32));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{1}$/', $generator->alphanumeric(1));
    }

    public function testEveryLetterAndDigitCanBeDrawn(): void
    {
        $generator = new SecretGenerator(new SeededRandomSource());
        $seen = count_chars($generator->alphanumeric(20000), 3);

        self::assertSame(62, strlen($seen));
    }

    public function testAPrefixedIdIsThePrefixAnUnderscoreAndSixteenCharacters(): void
    {
        $generator = new SecretGenerator(new SeededRandomSource());

        self::assertMatchesRegularExpression('/^rol_[A-Za-z0-9]{16}$/', $generator->prefixedId('rol'));
        self::assertMatchesRegularExpression('/^rs_[A-Za-z0-9]{16}$/', $generator->prefixedId('rs'));
    }
}
