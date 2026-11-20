<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Mfa;

use Clavia\Domain\Authentication\Mfa\Base32;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    /**
     * RFC 6238 Appendix B, SHA-1: the reference values are eight digits, and dynamic
     * truncation is the same at six, so the last six of each are this server's codes.
     */
    #[DataProvider('rfc6238')]
    public function testTheCodesMatchTheRfc6238Vectors(int $timestamp, string $expected): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));

        self::assertSame($expected, Totp::codeAt($secret, new DateTimeImmutable('@' . $timestamp)));
    }

    /** @return iterable<string, array{int, string}> */
    public static function rfc6238(): iterable
    {
        yield '59' => [59, '287082'];
        yield '1111111109' => [1111111109, '081804'];
        yield '1111111111' => [1111111111, '050471'];
        yield '1234567890' => [1234567890, '005924'];
        yield '2000000000' => [2000000000, '279037'];
        yield '20000000000' => [20000000000, '353130'];
    }

    public function testTheAdjacentStepsAreAcceptedAndTheMatchedOneIsReturned(): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(1));
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $step = Totp::timeStep($now);

        self::assertSame($step - 1, Totp::match($secret, $this->codeOffset($secret, $now, -1), $now, null));
        self::assertSame($step, Totp::match($secret, Totp::codeAt($secret, $now), $now, null));
        self::assertSame($step + 1, Totp::match($secret, $this->codeOffset($secret, $now, 1), $now, null));
        self::assertNull(Totp::match($secret, $this->codeOffset($secret, $now, -2), $now, null));
        self::assertNull(Totp::match($secret, $this->codeOffset($secret, $now, 2), $now, null));
    }

    public function testAStepAtOrBeforeTheLastOneUsedIsRefused(): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(1));
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $step = Totp::timeStep($now);
        $previous = $this->codeOffset($secret, $now, -1);

        self::assertNull(Totp::match($secret, $previous, $now, $step - 1));
        self::assertNull(Totp::match($secret, Totp::codeAt($secret, $now), $now, $step));
        self::assertSame($step + 1, Totp::match($secret, $this->codeOffset($secret, $now, 1), $now, $step));
    }

    #[DataProvider('malformed')]
    public function testMalformedInputMatchesNothing(string $code): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(1));

        self::assertNull(Totp::match($secret, $code, new DateTimeImmutable(), null));
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => [''];
        yield 'five digits' => ['12345'];
        yield 'seven digits' => ['1234567'];
        yield 'letters' => ['abcdef'];
        yield 'spaced' => ['12 34 56'];
        yield 'a trailing newline' => ["123456\n"];
        yield 'non-ASCII digits' => ['١٢٣٤٥٦'];
    }

    public function testTheProvisioningUriIsWhatAuthenticatorAppsExpect(): void
    {
        $secret = TotpSecret::fromBase32('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
        $uri = Totp::provisioningUri($secret, 'ada@clavia.dev', 'Clavia (t)');
        $parts = parse_url($uri);
        parse_str($parts['query'] ?? '', $query);

        self::assertSame('otpauth', $parts['scheme'] ?? null);
        self::assertSame('totp', $parts['host'] ?? null);
        self::assertSame('/Clavia (t):ada@clavia.dev', rawurldecode($parts['path'] ?? ''));
        self::assertSame([
            'secret' => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
            'issuer' => 'Clavia (t)',
            'algorithm' => 'SHA1',
            'digits' => '6',
            'period' => '30',
        ], $query);
    }

    public function testASeedIsTwentyRandomBytesAndRoundTripsThroughBase32(): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(1));

        self::assertSame(TotpSecret::BYTES, strlen($secret->bytes()));
        self::assertSame($secret->bytes(), TotpSecret::fromBase32($secret->base32())->bytes());
        self::assertNotSame($secret->bytes(), TotpSecret::generate(new SeededRandomSource(2))->bytes());
    }

    public function testASeedShorterThan128BitsIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        TotpSecret::fromBase32(Base32::encode(str_repeat('a', 15)));
    }

    public function testASeedIsNotPrintedByADump(): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(1));

        self::assertStringNotContainsString($secret->base32(), print_r($secret, true));
        self::assertStringNotContainsString(bin2hex($secret->bytes()), bin2hex(print_r($secret, true)));
    }

    private function codeOffset(TotpSecret $secret, DateTimeImmutable $now, int $steps): string
    {
        return Totp::codeAt($secret, $now->modify(sprintf('%+d seconds', $steps * Totp::PERIOD)));
    }
}
