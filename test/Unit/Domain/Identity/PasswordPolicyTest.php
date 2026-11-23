<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function testEightCharactersAreEnoughAndSeventyTwoBytesTheMost(): void
    {
        self::assertSame('12345678', PasswordPolicy::accept('12345678'));
        self::assertSame(str_repeat('a', 72), PasswordPolicy::accept(str_repeat('a', 72)));
        // Characters, not bytes, for the minimum: eight accented letters are eight.
        self::assertSame(str_repeat('é', 8), PasswordPolicy::accept(str_repeat('é', 8)));
    }

    #[DataProvider('refused')]
    public function testAnythingElseIsRefusedWithoutRepeatingIt(string $password): void
    {
        try {
            PasswordPolicy::accept($password);
            self::fail('The password was accepted.');
        } catch (InvalidValue $refusal) {
            self::assertStringNotContainsString($password, $refusal->getMessage());
        }
    }

    /** @return iterable<string, array{string}> */
    public static function refused(): iterable
    {
        yield 'seven characters' => ['1234567'];
        // A bound on the work one sign-in asks of the hash, counted in bytes.
        yield '1,025 bytes' => [str_repeat('a', 1025)];
        yield '342 euro signs, 1,026 bytes' => [str_repeat('€', 342)];
        yield 'not UTF-8' => ["\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"];
        yield 'a NUL byte' => ["password\0suffix"];
    }
}
