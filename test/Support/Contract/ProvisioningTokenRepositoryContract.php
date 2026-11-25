<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\PageRequest;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ProvisioningTokenRepository} must do, run against the double and PostgreSQL.
 */
trait ProvisioningTokenRepositoryContract
{
    abstract protected function provisioningTokens(): ProvisioningTokenRepository;

    abstract protected function connections(): ConnectionRepository;

    #[Test]
    public function anIssuedProvisioningTokenIsReadBackWhole(): void
    {
        $token = $this->aProvisioningToken('entra', 'staff');
        $this->provisioningTokens()->add($token);

        $stored = $this->provisioningTokens()->find($token->id);

        self::assertNotNull($stored);
        self::assertTrue($stored->digest->equals(Digest::of('entra')));
        self::assertSame('staff', $stored->connection->value);
        self::assertSame('For entra', $stored->description);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->createdAt);
        self::assertEquals(new DateTimeImmutable('2027-01-15T10:00:00Z'), $stored->expiresAt);
        self::assertNull($stored->revokedAt);
        self::assertSame(SubjectAttribute::UserName, $stored->subjectAttribute);
        self::assertTrue($stored->addressesTrusted);
        self::assertFalse($stored->deleteDeactivates);
        self::assertNull($this->provisioningTokens()->find(ProvisioningTokenId::generate(new SeededRandomSource(99))));
        self::assertTrue($this->provisioningTokens()->findByDigest(Digest::of('entra'))?->id->equals($token->id));
        self::assertNull($this->provisioningTokens()->findByDigest(Digest::of('nobody')));
    }

    #[Test]
    public function savingAProvisioningTokenRecordsItsRevocation(): void
    {
        $token = $this->aProvisioningToken('entra', 'staff');
        $this->provisioningTokens()->add($token);

        $this->provisioningTokens()->save($token->revoke(new DateTimeImmutable('2026-01-17T10:00:00Z')));

        self::assertEquals(
            new DateTimeImmutable('2026-01-17T10:00:00Z'),
            $this->provisioningTokens()->find($token->id)?->revokedAt,
        );
    }

    #[Test]
    public function provisioningTokensArePagedNewestFirstByConnectionAndDescription(): void
    {
        $this->provisioningTokens()->add($this->aProvisioningToken('older', 'staff', '2026-01-14T10:00:00Z'));
        $this->provisioningTokens()->add($this->aProvisioningToken('newer', 'staff', '2026-01-15T10:00:00Z'));
        $this->provisioningTokens()->add($this->aProvisioningToken('other', 'contractors', '2026-01-16T10:00:00Z'));

        $all = $this->provisioningTokens()->page(PageRequest::of(1, 10, ''));
        $staff = $this->provisioningTokens()->page(PageRequest::of(1, 10, ''), ConnectionName::fromString('staff'));
        $found = $this->provisioningTokens()->page(PageRequest::of(1, 10, 'OLD'), ConnectionName::fromString('staff'));
        $none = $this->provisioningTokens()->page(
            PageRequest::of(1, 10, 'other'),
            ConnectionName::fromString('staff'),
        );

        self::assertSame(['For other', 'For newer', 'For older'], array_map(
            static fn (ProvisioningToken $token): string => $token->description,
            $all->items,
        ));
        self::assertSame(2, $staff->total);
        self::assertSame(['For newer', 'For older'], array_map(
            static fn (ProvisioningToken $token): string => $token->description,
            $staff->items,
        ));
        self::assertSame(1, $found->total);
        self::assertSame(0, $none->total, 'The search is within the connection.');
    }

    private function aProvisioningToken(
        string $secret,
        string $connection,
        string $at = '2026-01-15T10:00:00Z',
    ): ProvisioningToken {
        $name = ConnectionName::fromString($connection);
        if ($this->connections()->find($name) === null) {
            $this->connections()->add(
                Connection::pool($name, ucfirst($connection), true, false, new DateTimeImmutable($at)),
            );
        }

        return ProvisioningToken::issue(
            ProvisioningTokenId::generate(new SeededRandomSource(crc32($secret))),
            Digest::of($secret),
            $name,
            'For ' . $secret,
            new DateTimeImmutable($at),
            ProvisioningToken::DEFAULT_LIFETIME_SECONDS,
            SubjectAttribute::UserName,
            true,
            false,
        );
    }
}
