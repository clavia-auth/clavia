<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\Redemption;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see AuthorizationCodeRepository} must do.
 */
trait AuthorizationCodeRepositoryContract
{
    abstract protected function codes(): AuthorizationCodeRepository;

    /**
     * Run `$work` inside a transaction of the storage under test.
     *
     * @template T
     * @param callable(): T $work
     * @return T
     */
    abstract protected function transactional(callable $work): mixed;

    /**
     * A client and a user that exist in the storage under test, for a code to belong to.
     *
     * @return array{ClientId, UserId}
     */
    abstract protected function anOwner(): array;

    #[Test]
    public function anAddedCodeIsReadBackWholeByItsDigest(): void
    {
        $code = $this->aCode('the-code');
        $this->codes()->add($code);

        $stored = $this->locked('the-code');

        self::assertNotNull($stored);
        self::assertTrue($stored->id->equals($code->id));
        self::assertTrue($stored->digest->equals($code->digest));
        self::assertTrue($stored->clientId->equals($code->clientId));
        self::assertTrue($stored->userId->equals($code->userId));
        self::assertSame('https://app.example/cb?x=1', $stored->redirectUri);
        self::assertSame('openid profile', $stored->scope->toString());
        self::assertSame($code->challenge->value, $stored->challenge->value);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:01:00Z'), $stored->expiresAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->createdAt);
        self::assertNull($stored->usedAt());
    }

    #[Test]
    public function whatTheIdTokenWillReportIsReadBackAsIssued(): void
    {
        $authenticatedAt = new DateTimeImmutable('2026-01-15T09:58:12.250000Z');
        $this->codes()->add($this->aCode(
            'oidc-code',
            Nonce::fromString('n-0S6_WzA2Mj'),
            AuthenticationContext::reconstitute($authenticatedAt, [AuthenticationMethod::Password], 'session-sid'),
        ));

        $stored = $this->locked('oidc-code');

        self::assertNotNull($stored);
        self::assertSame('n-0S6_WzA2Mj', $stored->nonce?->value);
        self::assertEquals($authenticatedAt, $stored->authentication->authenticatedAt);
        self::assertSame(['pwd'], $stored->authentication->methodValues());
        self::assertSame('session-sid', $stored->authentication->sid);
    }

    #[Test]
    public function aCodeWithoutAnAuthenticationReportsNone(): void
    {
        $this->codes()->add($this->aCode('plain-code'));

        $stored = $this->locked('plain-code');

        self::assertNotNull($stored);
        self::assertNull($stored->nonce);
        self::assertNull($stored->authentication->authenticatedAt);
        self::assertSame([], $stored->authentication->methods);
        self::assertNull($stored->authentication->sid);
    }

    #[Test]
    public function anUnknownDigestIsNull(): void
    {
        $this->codes()->add($this->aCode('the-code'));

        self::assertNull($this->locked('another'));
    }

    #[Test]
    public function lockingOutsideATransactionIsRefused(): void
    {
        $this->codes()->add($this->aCode('the-code'));

        $this->expectException(LogicException::class);

        $this->codes()->lockForRedemption(Digest::of('the-code'));
    }

    #[Test]
    public function aSpentCodeIsStoredAsSpent(): void
    {
        $code = $this->aCode('the-code');
        $this->codes()->add($code);
        $now = new DateTimeImmutable('2026-01-15T10:00:30.250000Z');

        $this->transactional(function () use ($code, $now): void {
            $locked = $this->codes()->lockForRedemption(Digest::of('the-code'));
            self::assertNotNull($locked);
            self::assertSame(Redemption::Redeemed, $locked->redeem($code->clientId, $now));
            $this->codes()->save($locked);
        });

        $again = $this->locked('the-code');
        self::assertNotNull($again);
        self::assertEquals($now, $again->usedAt());
        self::assertSame(Redemption::Replayed, $again->redeem($code->clientId, $now));
    }

    #[Test]
    public function aCodeSpentInMemoryIsNotSpentUntilItIsSaved(): void
    {
        $code = $this->aCode('the-code');
        $this->codes()->add($code);

        $this->transactional(function () use ($code): void {
            $locked = $this->codes()->lockForRedemption(Digest::of('the-code'));
            self::assertNotNull($locked);
            self::assertSame(
                Redemption::Redeemed,
                $locked->redeem($code->clientId, new DateTimeImmutable('2026-01-15T10:00:30Z')),
            );
        });

        $again = $this->locked('the-code');
        self::assertNull($again?->usedAt());
    }

    /** The stored code for a value, read the only way the port allows: locked, in a transaction. */
    private function locked(string $value): ?AuthorizationCode
    {
        return $this->transactional(
            fn (): ?AuthorizationCode => $this->codes()->lockForRedemption(Digest::of($value)),
        );
    }

    private function aCode(
        string $value,
        ?Nonce $nonce = null,
        ?AuthenticationContext $authentication = null,
    ): AuthorizationCode {
        [$clientId, $userId] = $this->anOwner();

        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            $clientId,
            $userId,
            'https://app.example/cb?x=1',
            ScopeSet::fromString('openid profile'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            $nonce,
            $authentication ?? AuthenticationContext::unknown(),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            60,
        );
    }
}
