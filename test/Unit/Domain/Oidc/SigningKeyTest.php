<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Oidc;

use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Oidc\SigningKeyStatus;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\TestSigningKeys;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SigningKeyTest extends TestCase
{
    public function testANewKeySignsAndIsPublishedForAsLongAsItDoes(): void
    {
        $key = SigningKey::activate(TestSigningKeys::publicJwk(), $this->at('10:00:00'));

        self::assertTrue($key->isActive());
        self::assertSame(SigningKeyStatus::Active, $key->status());
        self::assertNull($key->retiredAt());
        self::assertNull($key->publishedUntil());
        self::assertTrue($key->isPublishedAt($this->at('10:00:00')->modify('+10 years')));
        self::assertSame(TestSigningKeys::publicJwk()->kid, $key->kid());
    }

    public function testARetiredKeyStaysPublishedForItsGraceAndNotASecondLonger(): void
    {
        $key = SigningKey::activate(TestSigningKeys::publicJwk(), $this->at('10:00:00'));

        $key->retire($this->at('11:00:00'), 3600);

        self::assertFalse($key->isActive());
        self::assertEquals($this->at('11:00:00'), $key->retiredAt());
        self::assertEquals($this->at('12:00:00'), $key->publishedUntil());
        self::assertTrue($key->isPublishedAt($this->at('11:59:59')));
        self::assertFalse($key->isPublishedAt($this->at('12:00:00')));
    }

    public function testRetiringAgainDoesNotReopenThePublicationWindow(): void
    {
        $key = SigningKey::activate(TestSigningKeys::publicJwk(), $this->at('10:00:00'));
        $key->retire($this->at('11:00:00'), 60);

        $key->retire($this->at('11:00:30'), 86_400);

        self::assertEquals($this->at('11:00:00'), $key->retiredAt());
        self::assertEquals($this->at('11:01:00'), $key->publishedUntil());
    }

    #[DataProvider('contradictions')]
    public function testStoredDatesMustAgreeWithTheStatus(
        SigningKeyStatus $status,
        ?string $retiredAt,
        ?string $publishedUntil,
    ): void {
        $this->expectException(InvalidValue::class);

        SigningKey::reconstitute(
            TestSigningKeys::publicJwk(),
            $status,
            $this->at('10:00:00'),
            $retiredAt === null ? null : $this->at($retiredAt),
            $publishedUntil === null ? null : $this->at($publishedUntil),
        );
    }

    /** @return iterable<string, array{SigningKeyStatus, string|null, string|null}> */
    public static function contradictions(): iterable
    {
        yield 'an active key with a retirement' => [SigningKeyStatus::Active, '11:00:00', null];
        yield 'an active key with a publication end' => [SigningKeyStatus::Active, null, '12:00:00'];
        yield 'a retired key with neither date' => [SigningKeyStatus::Retired, null, null];
        yield 'a retired key with no publication end' => [SigningKeyStatus::Retired, '11:00:00', null];
    }

    private function at(string $time): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T' . $time . 'Z');
    }
}
