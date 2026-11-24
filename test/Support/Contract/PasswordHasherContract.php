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
        yield 'bcrypt' => ['$2y$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'];
        yield 'a NUL byte' => ["\0"];
    }

    #[DataProvider('malformedHashes')]
    public function testAMalformedHashIsNotAMatchAndNotAnError(string $hash): void
    {
        self::assertFalse($this->hasher()->verify('a-secret', $hash));
        self::assertFalse($this->hasher()->canVerify($hash));
    }

    public function testItRecognisesItsOwnHashes(): void
    {
        self::assertTrue($this->hasher()->canVerify($this->hasher()->hash('a-secret')));
    }

    public function testASecretOfMoreThan1024BytesIsRefused(): void
    {
        $hasher = $this->hasher();
        self::assertTrue($hasher->verify(str_repeat('a', 1024), $hasher->hash(str_repeat('a', 1024))));

        $this->expectException(SecretNotHashable::class);

        $hasher->hash(str_repeat('a', 1025));
    }

    public function testTheWholeSecretCounts(): void
    {
        // No truncation: two long secrets differing only in their last byte are two secrets.
        $hasher = $this->hasher();
        $hash = $hasher->hash(str_repeat('a', 1000) . 'x');

        self::assertFalse($hasher->verify(str_repeat('a', 1000) . 'y', $hash));
        self::assertFalse($hasher->verify(str_repeat('a', 1000), $hash));
    }

    public function testANulByteIsPartOfTheSecret(): void
    {
        // Hashed faithfully, not cut at the NUL: "before" alone is another secret.
        $hasher = $this->hasher();
        $hash = $hasher->hash("before\0after");

        self::assertTrue($hasher->verify("before\0after", $hash));
        self::assertFalse($hasher->verify('before', $hash));
    }

    public function testTheLimitIsInBytesNotCharacters(): void
    {
        $hasher = $this->hasher();

        // 341 three-byte characters are 1,023 bytes; one more character is over.
        self::assertTrue($hasher->verify(str_repeat('€', 341), $hasher->hash(str_repeat('€', 341))));

        $this->expectException(SecretNotHashable::class);

        $hasher->hash(str_repeat('€', 342));
    }

    public function testSimulatingAVerificationAcceptsAnySecretAndLeavesNothingBehind(): void
    {
        $hasher = $this->hasher();
        $hash = $hasher->hash('the-secret');

        // Whatever an attacker types reaches this path: nothing may make it throw.
        $hasher->simulateVerification('');
        $hasher->simulateVerification(str_repeat('a', 2000));
        $hasher->simulateVerification("before\0after");

        self::assertTrue($hasher->verify('the-secret', $hash));
    }
}
