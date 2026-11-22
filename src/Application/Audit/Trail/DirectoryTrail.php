<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit\Trail;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Identity\Event\IdentityUnlinked;
use Clavia\Domain\Identity\Event\EmailVerified;
use Clavia\Domain\Identity\Event\PasswordLinkSent;
use Clavia\Domain\Identity\Event\PasswordReset;
use Clavia\Domain\Identity\Event\UserChanged;
use Clavia\Domain\Identity\Event\UserCreated;
use Clavia\Domain\Identity\Event\UserSignedUp;
use Clavia\Domain\Identity\Event\UserDeleted;
use Clavia\Domain\Rbac\Event\RoleChanged;
use Clavia\Domain\Rbac\Event\RoleCreated;
use Clavia\Domain\Rbac\Event\RoleDeleted;
use Clavia\Domain\Rbac\Event\RoleGiven;
use Clavia\Domain\Rbac\Event\RoleTaken;
use Clavia\Domain\Rbac\Event\UserRolesReplaced;
use Clavia\Domain\Rbac\RoleId;

/**
 * Accounts, their linked identities, roles and who holds them — in the audit trail.
 *
 * Every change to what a person holds is recorded against the person, so an account's
 * history answers "how did they come to hold this?"; the role's own history is its
 * creation, changes and deletion. The actor is the request's caller.
 */
final readonly class DirectoryTrail implements EventSubscriber
{
    public function __construct(private Audit $audit)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            UserCreated::class => $this->userCreated(...),
            UserSignedUp::class => $this->userSignedUp(...),
            EmailVerified::class => $this->emailVerified(...),
            PasswordReset::class => $this->passwordReset(...),
            PasswordLinkSent::class => $this->passwordLinkSent(...),
            UserChanged::class => $this->userChanged(...),
            UserDeleted::class => $this->userDeleted(...),
            IdentityUnlinked::class => $this->identityUnlinked(...),
            RoleCreated::class => $this->roleCreated(...),
            RoleChanged::class => $this->roleChanged(...),
            RoleDeleted::class => $this->roleDeleted(...),
            RoleGiven::class => $this->roleGiven(...),
            RoleTaken::class => $this->roleTaken(...),
            UserRolesReplaced::class => $this->userRolesReplaced(...),
        ];
    }

    private function userCreated(UserCreated $event): void
    {
        $user = $event->user;
        $this->audit->record(AuditEventType::UserCreated, AuditTarget::user($user->id), [
            'connection' => $user->connection->value,
            'email' => $user->email,
        ]);
    }

    /** The person acted on their own account: they are the actor, through the sign-up page. */
    private function userSignedUp(UserSignedUp $event): void
    {
        $user = $event->user;
        $this->audit->record(AuditEventType::UserSignedUp, AuditTarget::user($user->id), [
            'connection' => $user->connection->value,
            'email' => $user->email,
        ], Actor::person($user->id));
    }

    private function emailVerified(EmailVerified $event): void
    {
        $this->audit->record(
            AuditEventType::UserEmailVerified,
            AuditTarget::user($event->userId),
            actor: Actor::person($event->userId),
        );
    }

    private function passwordReset(PasswordReset $event): void
    {
        $this->audit->record(
            AuditEventType::UserPasswordReset,
            AuditTarget::user($event->userId),
            actor: Actor::person($event->userId),
        );
    }

    /** The operator is the actor; the detail says which of the two mails it was, never the link. */
    private function passwordLinkSent(PasswordLinkSent $event): void
    {
        $this->audit->record(AuditEventType::UserPasswordLinkSent, AuditTarget::user($event->userId), [
            'kind' => $event->invitation ? 'invitation' : 'reset',
        ]);
    }

    private function userChanged(UserChanged $event): void
    {
        $this->audit->record(AuditEventType::UserUpdated, AuditTarget::user($event->userId), [
            'fields' => $event->changed,
            'deactivated' => $event->deactivated,
        ]);
    }

    private function userDeleted(UserDeleted $event): void
    {
        $this->audit->record(AuditEventType::UserDeleted, AuditTarget::user($event->user->id), [
            'email' => $event->user->email,
        ]);
    }

    private function identityUnlinked(IdentityUnlinked $event): void
    {
        $this->audit->record(AuditEventType::UserIdentityUnlinked, AuditTarget::user($event->userId), [
            'connection' => $event->connection->value,
        ]);
    }

    private function roleCreated(RoleCreated $event): void
    {
        $this->audit->record(AuditEventType::RoleCreated, AuditTarget::role($event->role->id), [
            'name' => $event->role->name,
        ]);
    }

    private function roleChanged(RoleChanged $event): void
    {
        $this->audit->record(AuditEventType::RoleUpdated, AuditTarget::role($event->roleId), [
            'fields' => $event->changed,
        ]);
    }

    private function roleDeleted(RoleDeleted $event): void
    {
        $this->audit->record(AuditEventType::RoleDeleted, AuditTarget::role($event->role->id), [
            'name' => $event->role->name,
        ]);
    }

    private function roleGiven(RoleGiven $event): void
    {
        $this->audit->record(AuditEventType::UserRolesChanged, AuditTarget::user($event->userId), [
            'given' => [$event->roleId->value],
        ]);
    }

    private function roleTaken(RoleTaken $event): void
    {
        $this->audit->record(AuditEventType::UserRolesChanged, AuditTarget::user($event->userId), [
            'taken' => [$event->roleId->value],
        ]);
    }

    private function userRolesReplaced(UserRolesReplaced $event): void
    {
        $this->audit->record(AuditEventType::UserRolesChanged, AuditTarget::user($event->userId), [
            'roles' => array_map(static fn (RoleId $role): string => $role->value, $event->roles),
        ]);
    }
}
