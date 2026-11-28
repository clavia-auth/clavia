<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Domain\Authorization\Event\AuthorizationEnabled;
use Clavia\Domain\Authorization\Event\AuthorizationModelWritten;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\Client\Event\ClientDeleted;
use Clavia\Domain\Identity\Event\UserDeleted;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\Event\RoleChanged;
use Clavia\Domain\Rbac\Event\RoleDeleted;
use Clavia\Domain\Rbac\Event\RoleGiven;
use Clavia\Domain\Rbac\Event\RoleTaken;
use Clavia\Domain\Rbac\Event\UserRolesReplaced;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\Event\ResourceServerChanged;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;

/**
 * What Clavia knows of people, fed to the decision engine (docs/design/fine-grained-authorization.md
 * §5.4): each change to who holds a role, to what a role grants, or to who exists, queues an entry in
 * the identity feed's outbox for each API store it may touch, in the transaction of the change; the
 * entries are sent after the response, and `fga:sync` sends what failed.
 *
 * An entry says what to bring into step, never what to write ({@see \Clavia\Domain\Authorization\FeedSubject}):
 * the events say what is now, not what was, and what the sender reads when it sends is the truth.
 */
final class IdentityFeed implements EventSubscriber
{
    /** What a send after the response may take: the cron picks up the rest. */
    private const int AFTER_RESPONSE_SECONDS = 5;

    /** Whether a send after this response is already asked for. */
    private bool $sendDeferred = false;

    /**
     * @param bool $available Whether fine-grained authorization is on (`CLAVIA_FGA_URL`). Off, entries
     *                        are still queued for the APIs that kept a store, one per subject, and sent
     *                        once it is on again: nothing that happened meanwhile is lost.
     */
    public function __construct(
        private readonly IdentityFeedOutbox $outbox,
        private readonly ResourceServerRepository $resourceServers,
        private readonly RoleRepository $roles,
        private readonly SyncIdentityFeed $sync,
        private readonly DeferredTasks $deferred,
        private readonly Clock $clock,
        private readonly bool $available,
    ) {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            RoleGiven::class => $this->roleGiven(...),
            RoleTaken::class => $this->roleTaken(...),
            UserRolesReplaced::class => $this->userRolesReplaced(...),
            RoleChanged::class => $this->roleChanged(...),
            RoleDeleted::class => $this->roleDeleted(...),
            UserDeleted::class => $this->userDeleted(...),
            ClientDeleted::class => $this->clientDeleted(...),
            AuthorizationEnabled::class => $this->authorizationEnabled(...),
            AuthorizationModelWritten::class => $this->modelWritten(...),
            ResourceServerChanged::class => $this->apiChanged(...),
        ];
    }

    private function roleGiven(RoleGiven $event): void
    {
        $this->membershipChanged($event->roleId, $event->userId);
    }

    private function roleTaken(RoleTaken $event): void
    {
        $this->membershipChanged($event->roleId, $event->userId);
    }

    /** Everything a person holds replaced: what they held is gone, so every store. */
    private function userRolesReplaced(UserRolesReplaced $event): void
    {
        $this->everywhere(FeedSubject::user($event->userId));
    }

    /** What a role grants moved between APIs: its members, in every store, since what it was is gone. */
    private function roleChanged(RoleChanged $event): void
    {
        if (in_array('permissions', $event->changed, true)) {
            $this->everywhere(FeedSubject::role($event->roleId));
        }
    }

    private function roleDeleted(RoleDeleted $event): void
    {
        $this->everywhere(FeedSubject::role($event->role->id));
    }

    private function userDeleted(UserDeleted $event): void
    {
        $this->everywhere(FeedSubject::user($event->user->id));
    }

    private function clientDeleted(ClientDeleted $event): void
    {
        $this->everywhere(FeedSubject::client($event->client->id));
    }

    private function authorizationEnabled(AuthorizationEnabled $event): void
    {
        $this->wholeStore($event->resourceServerId);
    }

    private function modelWritten(AuthorizationModelWritten $event): void
    {
        $this->wholeStore($event->resourceServerId);
    }

    /**
     * An API's permissions changed: a permission withdrawn is withdrawn from every role holding it, so
     * the store's role memberships are worked out again.
     */
    private function apiChanged(ResourceServerChanged $event): void
    {
        if (in_array('permissions', $event->changed, true)) {
            $this->wholeStore($event->resourceServerId);
        }
    }

    /**
     * A role given or taken: the person, in the stores of the APIs the role holds a permission on.
     * Stores it no longer reaches lost its members when its permissions moved.
     */
    private function membershipChanged(RoleId $roleId, UserId $userId): void
    {
        $role = $this->roles->find($roleId);
        $this->queue(
            array_values(array_filter(
                $this->apis(),
                static fn (ResourceServer $api): bool => $role === null || ! $role->grantsOn($api->id)->isEmpty(),
            )),
            FeedSubject::user($userId),
        );
    }

    /** Authorization switched on, or a new model: every role's members, as `fga:resync` writes them. */
    private function wholeStore(ResourceServerId $id): void
    {
        $api = $this->resourceServers->find($id);
        if ($api !== null && $api->authorization !== null) {
            $this->queue([$api], FeedSubject::everyRole());
        }
    }

    private function everywhere(FeedSubject $subject): void
    {
        $this->queue($this->apis(), $subject);
    }

    /** @param list<ResourceServer> $apis */
    private function queue(array $apis, FeedSubject $subject): void
    {
        if ($apis === []) {
            return;
        }
        foreach ($apis as $api) {
            $this->outbox->enqueue($api->id, [$subject], $this->clock->now());
        }
        if ($this->available) {
            $this->sendAfterTheResponse();
        }
    }

    /**
     * Once per response, whatever was queued: by then the change has committed, or rolled back and
     * queued nothing.
     */
    private function sendAfterTheResponse(): void
    {
        if ($this->sendDeferred) {
            return;
        }
        $this->sendDeferred = true;
        $this->deferred->defer(function (): void {
            $this->sendDeferred = false;
            ($this->sync)(self::AFTER_RESPONSE_SECONDS);
        });
    }

    /**
     * The APIs with a store, switched on or off: a store switched off keeps its relationships, and is
     * kept in step for when it is switched on again.
     *
     * @return list<ResourceServer>
     */
    private function apis(): array
    {
        return $this->resourceServers->withAuthorization();
    }
}
