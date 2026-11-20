<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DigestTest extends TestCase
{
    public function testItIsTheSha256OfTheSecretInHexadecimal(): void
    {
        // The well-known SHA-256 test vector for "abc" (FIPS 180-4).
        self::assertSame(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
            Digest::of('abc')->toString(),
        );
    }

    public function testItIsDeterministicSoATokenCanBeLookedUpByItsDigest(): void
    {
        self::assertTrue(Digest::of('a-token')->equals(Digest::of('a-token')));
        self::assertFalse(Digest::of('a-token')->equals(Digest::of('another-token')));
    }

    public function testItRecognisesTheSecretItWasMadeFrom(): void
    {
        $digest = Digest::of('a-token');

        self::assertTrue($digest->matches('a-token'));
        self::assertFalse($digest->matches('a-token '));
        self::assertFalse($digest->matches(''));
    }

    public function testItSurvivesARoundTripThroughStorage(): void
    {
        $stored = Digest::of('a-token')->toString();

        self::assertTrue(Digest::fromHex($stored)->matches('a-token'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function valuesThatAreNotDigests(): iterable
    {
        yield 'empty' => [''];
        yield 'too short' => [str_repeat('a', 63)];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'upper case' => [str_repeat('A', 64)];
        yield 'not hexadecimal' => [str_repeat('g', 64)];
        yield 'a trailing newline' => [str_repeat('a', 64) . "\n"];
    }

    #[DataProvider('valuesThatAreNotDigests')]
    public function testOnlySixtyFourLowerCaseHexCharactersAreADigest(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Digest::fromHex($value);
    }
}
