<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Crypto;

use Clavia\Adapter\Secondary\Crypto\Pbkdf2PasswordHasher;
use Clavia\Application\Port\PasswordHasher;
use ClaviaTest\Support\Contract\PasswordHasherContract;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;

final class Pbkdf2PasswordHasherTest extends PasswordHasherContract
{
    /** The least SP 800-132 allows: these tests are about behaviour, not about being slow. */
    private const int TEST_ITERATIONS = 1000;

    /**
     * PBKDF2-HMAC-SHA-256 of "correct horse battery staple", salt "0123456789abcdef", 1,000
     * iterations, 32 bytes — computed by Python's hashlib, an implementation independent of OpenSSL's.
     */
    private const string KNOWN_ANSWER =
        '$pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$yqSq2SygY1sB4EcH9f2FG0JTMES+wqLsOT5YmiRBplI';

    #[\Override]
    protected function hasher(): PasswordHasher
    {
        return new Pbkdf2PasswordHasher(self::TEST_ITERATIONS);
    }

    public function testAHashNamesItsAlgorithmIterationsSaltAndKey(): void
    {
        self::assertMatchesRegularExpression(
            '#^\$pbkdf2-sha256\$i=1000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$#D',
            $this->hasher()->hash('a-secret'),
        );
        self::assertStringStartsWith('$pbkdf2-sha256$i=600000$', new Pbkdf2PasswordHasher()->hash('a-secret'));
    }

    public function testItVerifiesAnAnswerComputedElsewhere(): void
    {
        self::assertTrue($this->hasher()->verify('correct horse battery staple', self::KNOWN_ANSWER));
        self::assertFalse($this->hasher()->verify('correct horse battery stapler', self::KNOWN_ANSWER));
        // The iteration count is read from the hash, not from the hasher's own setting.
        self::assertTrue(new Pbkdf2PasswordHasher(5000)->verify('correct horse battery staple', self::KNOWN_ANSWER));
    }

    public function testAHashAtAnotherIterationCountNeedsARehash(): void
    {
        $current = new Pbkdf2PasswordHasher(2000);

        self::assertTrue($current->needsRehash(self::KNOWN_ANSWER));
        self::assertFalse($current->needsRehash($current->hash('a-secret')));
        self::assertTrue($current->needsRehash('$2y$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function tamperedHashes(): iterable
    {
        yield 'fewer iterations than SP 800-132 allows' => [str_replace('i=1000', 'i=999', self::KNOWN_ANSWER)];
        yield 'iterations past what a row may ask' => [str_replace('i=1000', 'i=99999999', self::KNOWN_ANSWER)];
        yield 'a short salt' => ['$pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFi$yqSq2SygY1sB4EcH9f2FG0JTMES+wqLsOT5YmiRBplI'];
        yield 'padding' => [self::KNOWN_ANSWER . '='];
        yield 'another digest' => [str_replace('sha256', 'sha1', self::KNOWN_ANSWER)];
        yield 'a trailing newline' => [self::KNOWN_ANSWER . "\n"];
    }

    #[DataProvider('tamperedHashes')]
    public function testATamperedHashNeverMatches(string $hash): void
    {
        self::assertFalse($this->hasher()->verify('correct horse battery staple', $hash));
    }

    public function testAnIterationCountOutsideSp800132IsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Pbkdf2PasswordHasher(999);
    }
}
