<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SecretNotHashable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What every {@see PasswordHasher} must do — the real adapter and the test double alike.
 */
abstract class PasswordHasherContract extends TestCase
{
    abstract protected function hasher(): PasswordHasher;

    public function testAHashVerifiesTheSecretItWasMadeFrom(): void
    {
        $hasher = $this->hasher();
        $hash = $hasher->hash('correct horse battery staple');

        self::assertTrue($hasher->verify('correct horse battery staple', $hash));
        self::assertFalse($hasher->verify('correct horse battery stapler', $hash));
        self::assertFalse($hasher->verify('', $hash));
    }

    public function testTheHashIsNotTheSecret(): void
    {
        $hash = $this->hasher()->hash('correct horse battery staple');

        self::assertStringNotContainsString('correct horse', $hash);
    }

    public function testTwoHashesOfOneSecretDiffer(): void
    {
        $hasher = $this->hasher();

        self::assertNotSame($hasher->hash('same-secret'), $hasher->hash('same-secret'));
    }

    public function testAFreshHashNeedsNoRehash(): void
    {
        $hasher = $this->hasher();

        self::assertFalse($hasher->needsRehash($hasher->hash('a-secret')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedHashes(): iterable
    {
        yield 'empty' => [''];
        yield 'plaintext' => ['a-secret'];
        yield 'another algorithm' => ['$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'];
        yield 'a truncated bcrypt hash' => ['$2y$12$abcdefghijklmnopqrstuu'];
        yield 'a NUL byte' => ["\0"];
    }

    #[DataProvider('malformedHashes')]
    public function testAMalformedHashIsNotAMatchAndNotAnError(string $hash): void
    {
        self::assertFalse($this->hasher()->verify('a-secret', $hash));
    }

    public function testASecretLongerThanSeventyTwoBytesIsRefusedRatherThanTruncated(): void
    {
        $hasher = $this->hasher();
        self::assertNotSame('', $hasher->hash(str_repeat('a', 72)));

        $this->expectException(SecretNotHashable::class);

        $hasher->hash(str_repeat('a', 73));
    }

    public function testALongerSecretNeverMatchesAHashOfItsFirstSeventyTwoBytes(): void
    {
        $hasher = $this->hasher();
        $hash = $hasher->hash(str_repeat('a', 72));

        self::assertTrue($hasher->verify(str_repeat('a', 72), $hash));
        self::assertFalse($hasher->verify(str_repeat('a', 72) . 'anything', $hash));
    }

    public function testASecretHoldingANulByteIsRefusedWhenHashingAndNeverMatches(): void
    {
        $hasher = $this->hasher();
        $hash = $hasher->hash('before');

        self::assertFalse($hasher->verify("before\0after", $hash));

        $this->expectException(SecretNotHashable::class);

        $hasher->hash("before\0after");
    }

    public function testTheLimitIsInBytesNotCharacters(): void
    {
        $hasher = $this->hasher();

        // 24 three-byte characters are exactly 72 bytes; one more character is over.
        self::assertTrue($hasher->verify(str_repeat('€', 24), $hasher->hash(str_repeat('€', 24))));

        $this->expectException(SecretNotHashable::class);

        $hasher->hash(str_repeat('€', 25));
    }
}
