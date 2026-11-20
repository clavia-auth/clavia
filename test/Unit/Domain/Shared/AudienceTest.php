<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AudienceTest extends TestCase
{
    public function testItIsComparedByteForByte(): void
    {
        $audience = Audience::fromString('https://management.clavia.test/api/v1/');

        self::assertTrue($audience->equals(Audience::fromString('https://management.clavia.test/api/v1/')));
        // An identifier, not a location: nothing is normalised.
        self::assertFalse($audience->equals(Audience::fromString('https://management.clavia.test/api/v1')));
        self::assertFalse($audience->equals(Audience::fromString('https://MANAGEMENT.clavia.test/api/v1/')));
    }

    public function testItNeedNotBeAUrl(): void
    {
        self::assertSame('urn:clavia:billing', Audience::fromString('urn:clavia:billing')->value);
        self::assertSame('billing-api', Audience::fromString('billing-api')->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function valuesThatAreNotAudiences(): iterable
    {
        yield 'empty' => [''];
        yield 'a space' => ['https://api.test/ v1'];
        yield 'a newline' => ["https://api.test/\n"];
        yield 'a NUL byte' => ["https://api.test/\0"];
        yield 'too long' => ['https://api.test/' . str_repeat('a', 2048)];
    }

    #[DataProvider('valuesThatAreNotAudiences')]
    public function testItRefusesWhatCannotIdentifyAnApi(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Audience::fromString($value);
    }
}
