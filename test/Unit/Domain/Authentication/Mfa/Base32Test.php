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
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base32Test extends TestCase
{
    /**
     * RFC 4648 §10, without the padding authenticator apps do not expect.
     */
    #[DataProvider('vectors')]
    public function testTheRfc4648VectorsEncodeAndDecode(string $bytes, string $encoded): void
    {
        self::assertSame($encoded, Base32::encode($bytes));
        self::assertSame($bytes, Base32::decode($encoded));
    }

    /** @return iterable<string, array{string, string}> */
    public static function vectors(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'f' => ['f', 'MY'];
        yield 'fo' => ['fo', 'MZXQ'];
        yield 'foo' => ['foo', 'MZXW6'];
        yield 'foob' => ['foob', 'MZXW6YQ'];
        yield 'fooba' => ['fooba', 'MZXW6YTB'];
        yield 'foobar' => ['foobar', 'MZXW6YTBOI'];
    }

    public function testDecodingForgivesCaseSpacesAndPadding(): void
    {
        self::assertSame('foobar', Base32::decode('mzxw 6ytb oi======'));
    }

    public function testEveryByteValueSurvivesTheRoundTrip(): void
    {
        $bytes = implode('', array_map(chr(...), range(0, 255)));

        self::assertSame($bytes, Base32::decode(Base32::encode($bytes)));
    }

    #[DataProvider('malformed')]
    public function testWhatIsNotBase32IsRefused(string $encoded): void
    {
        $this->expectException(InvalidValue::class);

        Base32::decode($encoded);
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'a digit outside the alphabet' => ['MZXW1'];
        yield 'a symbol' => ['MZ+W6'];
        yield 'a length no whole bytes have' => ['M'];
        yield 'leftover bits that are set' => ['MZ'];
    }
}
