<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ClientRegistrationRepository} must do, run against the double and PostgreSQL.
 */
trait ClientRegistrationRepositoryContract
{
    abstract protected function clientRegistrations(): ClientRegistrationRepository;

    abstract protected function clients(): ClientRepository;

    #[Test]
    public function aRegistrationIsReadBackByItsClient(): void
    {
        $client = $this->aSelfRegisteredClient('tpc_registered');
        $this->clientRegistrations()->add(new ClientRegistration(
            $client->id,
            Digest::of('registration-access-token'),
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $stored = $this->clientRegistrations()->find($client->id);

        self::assertNotNull($stored);
        self::assertTrue($stored->accessTokenDigest->equals(Digest::of('registration-access-token')));
        self::assertNull($stored->initialAccessTokenId);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->registeredAt);
        self::assertNull($this->clientRegistrations()->find(ClientId::fromString('tpc_nobody')));
    }

    #[Test]
    public function aRegistrationIsFoundByItsAccessTokenUntilItIsRotated(): void
    {
        $client = $this->aSelfRegisteredClient('tpc_rotating');
        $registration = new ClientRegistration(
            $client->id,
            Digest::of('first-token'),
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->clientRegistrations()->add($registration);

        $this->clientRegistrations()->save($registration->rotate(Digest::of('second-token')));

        self::assertNull($this->clientRegistrations()->findByAccessToken(Digest::of('first-token')));
        self::assertTrue(
            $this->clientRegistrations()->findByAccessToken(Digest::of('second-token'))?->clientId->equals($client->id),
        );
        self::assertEquals(
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            $this->clientRegistrations()->find($client->id)?->registeredAt,
        );
    }

    #[Test]
    public function theRegistrationsOfSeveralClientsAreReadTogether(): void
    {
        $first = $this->aSelfRegisteredClient('tpc_first');
        $second = $this->aSelfRegisteredClient('tpc_second');
        $this->aSelfRegisteredClient('tpc_operators');
        foreach ([$first, $second] as $client) {
            $this->clientRegistrations()->add(new ClientRegistration(
                $client->id,
                Digest::of('token-' . $client->id->value),
                null,
                new DateTimeImmutable('2026-01-15T10:00:00Z'),
            ));
        }

        $found = $this->clientRegistrations()->ofClients([
            $first->id,
            ClientId::fromString('tpc_operators'),
            $second->id,
        ]);

        self::assertEqualsCanonicalizing(
            ['tpc_first', 'tpc_second'],
            array_map(static fn (ClientRegistration $registration): string => $registration->clientId->value, $found),
        );
        self::assertSame([], $this->clientRegistrations()->ofClients([]));
    }

    #[Test]
    public function theFirstUseIsKeptAndTheUnusedAreFoundOldestFirst(): void
    {
        $at = static fn (string $day): DateTimeImmutable => new DateTimeImmutable($day . 'T10:00:00Z');
        foreach (
            ['tpc_used' => '2026-01-01', 'tpc_unused_old' => '2026-01-02', 'tpc_unused' => '2026-01-03',
            'tpc_recent' => '2026-01-20'] as $id => $day
        ) {
            $client = $this->aSelfRegisteredClient($id);
            $this->clientRegistrations()->add(new ClientRegistration($client->id, Digest::of($id), null, $at($day)));
        }
        $used = ClientId::fromString('tpc_used');

        $this->clientRegistrations()->markUsed($used, $at('2026-01-05'));
        $this->clientRegistrations()->markUsed($used, $at('2026-01-09'));
        $this->clientRegistrations()->markUsed(ClientId::fromString('tpc_nobody'), $at('2026-01-09'));

        $firstUse = $this->clientRegistrations()->find($used)?->firstUsedAt;
        self::assertEquals($at('2026-01-05'), $firstUse, 'The first one.');
        self::assertSame(
            ['tpc_unused_old', 'tpc_unused'],
            array_map(
                static fn (ClientId $id): string => $id->value,
                $this->clientRegistrations()->neverUsedSince($at('2026-01-15')),
            ),
        );
    }

    #[Test]
    public function aRegistrationGoesWithItsClient(): void
    {
        $client = $this->aSelfRegisteredClient('tpc_deleted');
        $this->clientRegistrations()->add(new ClientRegistration(
            $client->id,
            Digest::of('another-token'),
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $this->clients()->delete($client->id);

        self::assertNull($this->clientRegistrations()->find($client->id));
    }

    private function aSelfRegisteredClient(string $id): Client
    {
        $client = Client::register(
            ClientId::fromString($id),
            'Registered',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://app.example/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->clients()->save($client);

        return $client;
    }
}
