<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace ClaviaTest\Unit\Domain\Authentication;

use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Authentication\PasswordlessMode;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasswordlessChallengeTest extends TestCase
{
    private const string HANDLE = 'a-browser-held-handle-of-forty-three-chars';

    public function testACodeIsSixDigitsLeadingZerosIncluded(): void
    {
        $random = new SeededRandomSource(7);
        for ($i = 0; $i < 50; ++$i) {
            self::assertMatchesRegularExpression('/^\d{6}$/D', OneTimeCode::generate($random)->value);
        }
    }

    public function testATypedCodeToleratesSpacesAndDashes(): void
    {
        self::assertSame('012345', OneTimeCode::fromTyped(' 012 345 ')->value);
        self::assertSame('012345', OneTimeCode::fromTyped('012-345')->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notCodes(): iterable
    {
        yield 'empty' => [''];
        yield 'five digits' => ['12345'];
        yield 'seven digits' => ['1234567'];
        yield 'a letter' => ['12345a'];
        yield 'full-width digits' => ['１２３４５６'];
    }

    #[DataProvider('notCodes')]
    public function testAnythingElseIsNotACode(string $typed): void
    {
        $this->expectException(InvalidValue::class);

        OneTimeCode::fromTyped($typed);
    }

    public function testTheCodeAnswersOnlyTheHandleItWasBoundTo(): void
    {
        $code = OneTimeCode::fromTyped('123456');
        $challenge = PasswordlessChallenge::forCode('jane@example.com', self::HANDLE, $code, '/', null, null);

        self::assertTrue($challenge->acceptsCode(self::HANDLE, $code));
        self::assertFalse($challenge->acceptsCode(self::HANDLE, OneTimeCode::fromTyped('123457')));
        self::assertFalse($challenge->acceptsCode('another-browsers-handle', $code), 'Bound to the browser.');
        self::assertFalse(
            $challenge->codeDigest?->equals(Digest::of('123456')) ?? true,
            'What is stored is not the digest of six digits, a million guesses from the code.',
        );
    }

    public function testALinkAcceptsNoCode(): void
    {
        $challenge = PasswordlessChallenge::forLink('jane@example.com', '/', ClientId::fromString('spa'), 'state');

        self::assertTrue($challenge->isLink());
        self::assertNull($challenge->codeDigest);
        self::assertFalse($challenge->acceptsCode(self::HANDLE, OneTimeCode::fromTyped('123456')));
    }

    public function testACodeChallengeAndOnlyOneKeepsADigest(): void
    {
        try {
            new PasswordlessChallenge('jane@example.com', PasswordlessMode::Code, null, '/', null, null);
            self::fail('A code challenge without its digest was accepted.');
        } catch (InvalidValue) {
        }

        $this->expectException(InvalidValue::class);
        new PasswordlessChallenge('jane@example.com', PasswordlessMode::Link, Digest::of('x'), '/', null, null);
    }

    public function testAnAddressIsTrimmedAndLowerCased(): void
    {
        self::assertSame('jane@example.com', PasswordlessChallenge::address("  Jane@Example.COM \n"));
        self::assertSame('élodie@exemple.fr', PasswordlessChallenge::address('Élodie@Exemple.fr'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notAddresses(): iterable
    {
        yield 'empty' => [''];
        yield 'no at sign' => ['jane.example.com'];
        yield 'two at signs' => ['jane@doe@example.com'];
        yield 'no domain dot' => ['jane@localhost'];
        yield 'inner whitespace' => ['jane doe@example.com'];
        yield 'too long' => [str_repeat('a', 310) . '@example.com'];
        yield 'not UTF-8' => ["jane\xff@example.com"];
    }

    #[DataProvider('notAddresses')]
    public function testAnythingElseIsNotAnAddress(string $typed): void
    {
        $this->expectException(InvalidValue::class);

        PasswordlessChallenge::address($typed);
    }
}
