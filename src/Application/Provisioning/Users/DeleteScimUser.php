<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Domain\Identity\Event\UserChanged;
use Clavia\Domain\Identity\Event\UserDeleted;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `DELETE /scim/v2/Users/{id}` (RFC 7644 §3.6; docs/design/scim-provisioning.md §2, §5.3): the account
 * deleted, with its tokens, identities and provisioned record, its sessions ended and their
 * applications told. With the token's `delete_deactivates`, for an operator who must keep accounts,
 * it is deactivated instead, as `active: false` would.
 */
final readonly class DeleteScimUser
{
    public function __construct(
        private ReadScimUsers $read,
        private UserRepository $users,
        private SignOutEverywhere $signOut,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @return ScimUserRemoved|VersionMismatch|null Null when the connection has no such account.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ?array $ifMatch = null,
    ): ScimUserRemoved|VersionMismatch|null {
        $current = $this->read->find($caller, $id);
        if ($current === null) {
            return null;
        }
        if (! $current->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $user = $current->user;
        if ($caller->token->deleteDeactivates) {
            if ($user->isActive()) {
                $user->deactivate($this->clock->now());
                $this->users->save($user);
                $this->events->dispatch(new UserChanged($user->id, ['is_active'], true));
                ($this->signOut)($user->id);
            }

            return new ScimUserRemoved(true);
        }
        ($this->signOut)($user->id);
        $this->users->delete($user->id);
        $this->events->dispatch(new UserDeleted($user));

        return new ScimUserRemoved(false);
    }
}
