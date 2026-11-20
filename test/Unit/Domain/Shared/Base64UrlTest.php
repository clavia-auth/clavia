<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testItUsesTheUrlSafeAlphabetWithoutPadding(): void
    {
        // RFC 7515 Appendix C's example: the octets 3, 236, 255, 224, 193.
        self::assertSame('A-z_4ME', Base64Url::encode("\x03\xEC\xFF\xE0\xC1"));
        self::assertSame('', Base64Url::encode(''));
    }

    public function testDecodingReversesEncoding(): void
    {
        $bytes = random_bytes(97);

        self::assertSame($bytes, Base64Url::decode(Base64Url::encode($bytes)));
        self::assertSame("\x03\xEC\xFF\xE0\xC1", Base64Url::decode('A-z_4ME'));
    }

    #[DataProvider('notBase64Url')]
    public function testAnythingButCanonicalUnpaddedBase64UrlIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Base64Url::decode($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notBase64Url(): iterable
    {
        yield 'padding' => ['A-z_4ME='];
        yield 'the standard alphabet' => ['A+z/4ME'];
        yield 'whitespace' => ['A-z_ 4ME'];
        yield 'an impossible length' => ['A'];
        // "AB" and "AA" decode to the same byte; only the canonical form is accepted.
        yield 'non-zero trailing bits' => ['AB'];
    }
}
