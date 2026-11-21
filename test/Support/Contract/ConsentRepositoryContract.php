<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Clients;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ConsentRepository} does — the foreign keys included: deleting the
 * account, the application or the API takes the consent along.
 */
trait ConsentRepositoryContract
{
    abstract protected function consents(): ConsentRepository;

    abstract protected function users(): UserRepository;

    abstract protected function clients(): ClientRepository;

    abstract protected function resourceServers(): ResourceServerRepository;

    #[Test]
    public function aConsentIsFoundByPersonApplicationAndApiExactly(): void
    {
        [$user, $client, $api] = $this->consentParties();
        $other = $this->consentApi('rs_bbbbbbbbbbbbbbbb', 'https://other.example/');
        $this->consents()->save(self::consent($user, $client, $api, 'openid invoices:read', '10:00'));

        $found = $this->consents()->find($user, $client, $api);

        self::assertNotNull($found);
        self::assertSame('openid invoices:read', $found->scope->toString());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $found->grantedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $found->updatedAt);
        // `invoices:read` here says nothing about another API, nor about no API at all.
        self::assertNull($this->consents()->find($user, $client, $other));
        self::assertNull($this->consents()->find($user, $client, null));
    }

    #[Test]
    public function theNoApiConsentIsOneConsent(): void
    {
        [$user, $client] = $this->consentParties();
        $this->consents()->save(self::consent($user, $client, null, 'openid', '10:00'));
        $this->consents()->save(self::consent($user, $client, null, 'openid email', '10:00', '10:05'));

        self::assertSame('openid email', $this->consents()->find($user, $client, null)?->scope->toString());
        self::assertCount(1, $this->consents()->ofUser($user));
    }

    #[Test]
    public function savingReplacesTheConsentForTheSameTriple(): void
    {
        [$user, $client, $api] = $this->consentParties();
        $this->consents()->save(self::consent($user, $client, $api, 'openid', '10:00'));

        $widened = $this->consents()->find($user, $client, $api)?->widenedBy(
            ScopeSet::fromString('invoices:read'),
            new DateTimeImmutable('2026-01-15T11:00:00Z'),
        );
        self::assertNotNull($widened);
        $this->consents()->save($widened);

        $read = $this->consents()->find($user, $client, $api);
        self::assertSame('openid invoices:read', $read?->scope->toString());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $read?->grantedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:00Z'), $read?->updatedAt);
        self::assertCount(1, $this->consents()->ofUser($user));
    }

    #[Test]
    public function aPersonsConsentsAreListedOldestFirstAndOnlyTheirs(): void
    {
        [$user, $client, $api] = $this->consentParties();
        $stranger = $this->consentUser('00000000-0000-4000-8000-0000000000c2', 'stranger@example.com');
        $this->consents()->save(self::consent($user, $client, $api, 'invoices:read', '11:00'));
        $this->consents()->save(self::consent($user, $client, null, 'openid', '10:00'));
        $this->consents()->save(self::consent($stranger, $client, null, 'openid', '09:00'));

        $listed = $this->consents()->ofUser($user);

        self::assertCount(2, $listed);
        self::assertNull($listed[0]->resourceServerId);
        self::assertSame($api->value, $listed[1]->resourceServerId?->value);
    }

    #[Test]
    public function withdrawingTakesEveryApiOfThatApplicationOnly(): void
    {
        [$user, $client, $api] = $this->consentParties();
        $otherClient = $this->consentClient('tpc_other');
        $this->consents()->save(self::consent($user, $client, $api, 'invoices:read', '10:00'));
        $this->consents()->save(self::consent($user, $client, null, 'openid', '10:00'));
        $this->consents()->save(self::consent($user, $otherClient, null, 'openid', '10:00'));

        $this->consents()->withdraw($user, $client);
        $this->consents()->withdraw($user, ClientId::fromString('never-consented'));

        $left = $this->consents()->ofUser($user);
        self::assertCount(1, $left);
        self::assertSame('tpc_other', $left[0]->clientId->value);
    }

    #[Test]
    public function aConsentGoesWithWhatItNames(): void
    {
        [$user, $client, $api] = $this->consentParties();
        $this->consents()->save(self::consent($user, $client, $api, 'invoices:read', '10:00'));
        $this->consents()->save(self::consent($user, $client, null, 'openid', '10:00'));

        $this->resourceServers()->delete($api);
        self::assertNull($this->consents()->find($user, $client, $api));
        self::assertNotNull($this->consents()->find($user, $client, null));

        $this->clients()->delete($client);
        self::assertSame([], $this->consents()->ofUser($user));

        $other = $this->consentClient('tpc_other');
        $this->consents()->save(self::consent($user, $other, null, 'openid', '10:00'));
        $this->users()->delete($user);
        self::assertSame([], $this->consents()->ofUser($user));
    }

    /**
     * An account, a third-party application and an API, all stored.
     *
     * @return array{UserId, ClientId, ResourceServerId}
     */
    private function consentParties(): array
    {
        return [
            $this->consentUser('00000000-0000-4000-8000-0000000000c1', 'jane@example.com'),
            $this->consentClient('tpc_partner'),
            $this->consentApi('rs_aaaaaaaaaaaaaaaa', 'https://invoices.example/'),
        ];
    }

    private function consentUser(string $id, string $email): UserId
    {
        $user = User::register(UserId::fromString($id), $email, null, new DateTimeImmutable('2026-01-15T09:00:00Z'));
        $this->users()->save($user);

        return $user->id;
    }

    private function consentClient(string $id): ClientId
    {
        $client = Clients::public($id);
        $this->clients()->save($client);

        return $client->id;
    }

    private function consentApi(string $id, string $identifier): ResourceServerId
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString($id),
            Audience::fromString($identifier),
            'Invoices',
            [],
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
        );
        $this->resourceServers()->save($api);

        return $api->id;
    }

    private static function consent(
        UserId $user,
        ClientId $client,
        ?ResourceServerId $api,
        string $scope,
        string $grantedAt,
        ?string $updatedAt = null,
    ): UserConsent {
        return UserConsent::reconstitute(
            $user,
            $client,
            $api,
            ScopeSet::fromString($scope),
            new DateTimeImmutable('2026-01-15T' . $grantedAt . ':00Z'),
            new DateTimeImmutable('2026-01-15T' . ($updatedAt ?? $grantedAt) . ':00Z'),
        );
    }
}
