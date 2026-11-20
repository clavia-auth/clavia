<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PkceTest extends TestCase
{
    /** The worked example of RFC 7636, Appendix B. */
    private const string RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    private const string RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function testTheChallengeOfAVerifierIsTheOneTheRfcComputes(): void
    {
        $verifier = CodeVerifier::fromString(self::RFC_VERIFIER);

        self::assertSame(self::RFC_CHALLENGE, CodeChallenge::forVerifier($verifier)->value);
    }

    public function testAChallengeIsSatisfiedByItsVerifierAndNoOther(): void
    {
        $challenge = CodeChallenge::fromString(self::RFC_CHALLENGE);

        self::assertTrue($challenge->isSatisfiedBy(CodeVerifier::fromString(self::RFC_VERIFIER)));
        self::assertFalse($challenge->isSatisfiedBy(CodeVerifier::fromString(strrev(self::RFC_VERIFIER))));
    }

    public function testTheChallengeIsNotItsOwnVerifier(): void
    {
        // What `plain` would accept. S256 must not.
        $challenge = CodeChallenge::fromString(self::RFC_CHALLENGE);

        self::assertFalse($challenge->isSatisfiedBy(CodeVerifier::fromString(self::RFC_CHALLENGE)));
    }

    public function testAGeneratedVerifierIsValidAndSatisfiesItsOwnChallenge(): void
    {
        $random = new SeededRandomSource(1);

        $verifier = CodeVerifier::generate($random);
        $other = CodeVerifier::generate($random);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier->value);
        self::assertNotSame($verifier->value, $other->value);
        self::assertTrue(CodeChallenge::forVerifier($verifier)->isSatisfiedBy($verifier));
        self::assertFalse(CodeChallenge::forVerifier($verifier)->isSatisfiedBy($other));
    }

    #[DataProvider('verifiersInRange')]
    public function testAVerifierOf43To128UnreservedCharactersIsAccepted(string $value): void
    {
        self::assertSame($value, CodeVerifier::fromString($value)->value);
    }

    /** @return iterable<string, array{string}> */
    public static function verifiersInRange(): iterable
    {
        yield 'the shortest' => [str_repeat('a', 43)];
        yield 'the longest' => [str_repeat('a', 128)];
        yield 'every unreserved punctuation' => [str_repeat('a', 39) . '-._~'];
    }

    #[DataProvider('malformedVerifiers')]
    public function testAnyOtherVerifierIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        CodeVerifier::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedVerifiers(): iterable
    {
        yield 'empty' => [''];
        yield 'one too short' => [str_repeat('a', 42)];
        yield 'one too long' => [str_repeat('a', 129)];
        yield 'a space' => [str_repeat('a', 42) . ' '];
        yield 'a plus' => [str_repeat('a', 42) . '+'];
        yield 'a slash' => [str_repeat('a', 42) . '/'];
        yield 'padding' => [str_repeat('a', 42) . '='];
        yield 'a trailing newline' => [str_repeat('a', 43) . "\n"];
        yield 'non-ASCII' => [str_repeat('a', 42) . 'é'];
    }

    #[DataProvider('malformedChallenges')]
    public function testAChallengeIsExactlyTheBase64UrlOfASha256(string $value): void
    {
        $this->expectException(InvalidValue::class);

        CodeChallenge::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedChallenges(): iterable
    {
        yield 'empty' => [''];
        yield 'one too short' => [str_repeat('a', 42)];
        yield 'one too long' => [str_repeat('a', 44)];
        yield 'padded' => [str_repeat('a', 43) . '='];
        yield 'standard base64 alphabet' => [str_repeat('a', 42) . '+'];
        yield 'a dot' => [str_repeat('a', 42) . '.'];
        yield 'a trailing newline' => [str_repeat('a', 43) . "\n"];
    }

    public function testOnlyS256Exists(): void
    {
        self::assertSame('S256', CodeChallenge::METHOD);
    }
}
