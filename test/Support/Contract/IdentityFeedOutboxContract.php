<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Authorization\FeedEntry;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see IdentityFeedOutbox} must do (docs/design/fine-grained-authorization.md §5.4).
 */
trait IdentityFeedOutboxContract
{
    abstract protected function resourceServers(): ResourceServerRepository;

    abstract protected function identityFeedOutbox(): IdentityFeedOutbox;

    #[Test]
    public function aQueuedSubjectIsClaimedOnceWhileItsClaimLasts(): void
    {
        $api = $this->feedApi('https://documents.example/api/');
        $now = self::start();
        $ada = UserId::fromString('9b2f3c1e-0d5a-4e7b-8c6f-1a2b3c4d5e6f');
        $this->identityFeedOutbox()->enqueue($api, [FeedSubject::user($ada), FeedSubject::everyRole()], $now);

        $claimed = $this->claimAt(0, 10);

        self::assertSame(
            ['user:9b2f3c1e-0d5a-4e7b-8c6f-1a2b3c4d5e6f', '*'],
            array_map(static fn (FeedEntry $entry): string => $entry->subject->toString(), $claimed),
        );
        self::assertTrue($claimed[0]->resourceServerId->equals($api));
        self::assertSame(1, $claimed[0]->generation);
        self::assertSame(0, $claimed[0]->attempts);
        // Another worker finds nothing until the claim lapses.
        self::assertSame([], $this->claimAt(10, 10));
        self::assertCount(2, $this->claimAt(31, 10));
        self::assertSame(2, $this->identityFeedOutbox()->pending());
    }

    #[Test]
    public function aSubjectWaitsOncePerApiAndALimitIsHeld(): void
    {
        $documents = $this->feedApi('https://documents.example/api/');
        $invoices = $this->feedApi('https://invoices.example/api/');
        $now = self::start();
        $role = FeedSubject::role(RoleId::fromString('rol_AAAAAAAAAAAAAAAA'));
        $this->identityFeedOutbox()->enqueue($documents, [$role, $role], $now);
        $this->identityFeedOutbox()->enqueue($invoices, [$role], $now);
        $this->identityFeedOutbox()->enqueue($documents, [$role], $now);

        self::assertSame(2, $this->identityFeedOutbox()->pending());
        $first = $this->claimAt(0, 1);
        self::assertCount(1, $first);
        self::assertTrue($first[0]->resourceServerId->equals($documents));
        self::assertSame(3, $first[0]->generation);
    }

    #[Test]
    public function anEntryQueuedAgainWhileItWasSentIsKept(): void
    {
        $api = $this->feedApi('https://documents.example/api/');
        $now = self::start();
        $client = FeedSubject::client(ClientId::fromString('reports-backend'));
        $this->identityFeedOutbox()->enqueue($api, [$client], $now);
        $entry = self::first($this->claimAt(0, 10));

        $this->identityFeedOutbox()->enqueue($api, [$client], $now->modify('+1 second'));

        self::assertFalse($this->identityFeedOutbox()->settle($entry), 'A change came in while it was sent.');
        // Released, and due: the next pass reads Clavia again.
        $again = self::first($this->claimAt(2, 10));
        self::assertSame(2, $again->generation);
        self::assertTrue($this->identityFeedOutbox()->settle($again));
        self::assertSame(0, $this->identityFeedOutbox()->pending());
    }

    #[Test]
    public function aFailedSendIsCountedAndWaitsItsTurn(): void
    {
        $api = $this->feedApi('https://documents.example/api/');
        $now = self::start();
        $this->identityFeedOutbox()->enqueue($api, [FeedSubject::everyRole()], $now);
        $entry = self::first($this->claimAt(0, 10));

        $this->identityFeedOutbox()->postpone($entry, $now->modify('+5 seconds'));

        self::assertSame([], $this->claimAt(4, 10));
        $retried = self::first($this->claimAt(5, 10));
        self::assertSame(1, $retried->attempts);

        // A change while it waits makes it due now, its failures still counted.
        $this->identityFeedOutbox()->postpone($retried, $now->modify('+10 minutes'));
        $this->identityFeedOutbox()->enqueue($api, [FeedSubject::everyRole()], $now->modify('+6 seconds'));
        $due = self::first($this->claimAt(6, 10));
        self::assertSame(2, $due->attempts);
    }

    #[Test]
    public function anApiDeletedTakesItsEntriesAlong(): void
    {
        $api = $this->feedApi('https://documents.example/api/');
        $now = self::start();
        $this->identityFeedOutbox()->enqueue($api, [FeedSubject::everyRole()], $now);

        $this->resourceServers()->delete($api);

        self::assertSame(0, $this->identityFeedOutbox()->pending());
    }

    /**
     * Claim, `$seconds` after the test's start, for the thirty seconds a worker holds an entry.
     *
     * @param positive-int $limit
     *
     * @return list<FeedEntry>
     */
    private function claimAt(int $seconds, int $limit): array
    {
        $at = self::start()->modify(sprintf('+%d seconds', $seconds));

        return $this->identityFeedOutbox()->claim($at, $at->modify('+30 seconds'), $limit);
    }

    private static function start(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-11-28T10:00:00Z');
    }

    /** @param list<FeedEntry> $claimed */
    private static function first(array $claimed): FeedEntry
    {
        return $claimed[0] ?? self::fail('Nothing was claimed.');
    }

    private function feedApi(string $identifier): ResourceServerId
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            'Documents',
            [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->resourceServers()->save($api);

        return $api->id;
    }
}
