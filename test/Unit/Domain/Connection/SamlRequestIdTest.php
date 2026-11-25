<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Connection;

use Clavia\Domain\Connection\Saml\SamlRequestId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The `ID` of an `AuthnRequest`: an NCName (SAML Core §1.3.4), so it never starts with a digit. */
final class SamlRequestIdTest extends TestCase
{
    public function testItIsAnUnderscoreAndThirtyTwoRandomBytes(): void
    {
        $id = SamlRequestId::generate(new SeededRandomSource(1));

        self::assertMatchesRegularExpression('/^_[0-9a-f]{64}$/D', $id->value);
        self::assertNotSame($id->value, SamlRequestId::generate(new SeededRandomSource(2))->value);
        self::assertTrue($id->equals(SamlRequestId::fromString($id->value)));
    }

    /** @return iterable<string, array{0: string}> */
    public static function notIds(): iterable
    {
        yield 'empty' => [''];
        yield 'no underscore' => [str_repeat('a', 65)];
        yield 'short' => ['_' . str_repeat('a', 63)];
        yield 'upper case' => ['_' . str_repeat('A', 64)];
        yield 'a trailing newline' => ['_' . str_repeat('a', 64) . "\n"];
    }

    #[DataProvider('notIds')]
    public function testAnythingElseIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);
        SamlRequestId::fromString($value);
    }
}
