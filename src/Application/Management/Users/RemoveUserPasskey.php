<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\Event\PasskeyRemoved;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `DELETE /api/v1/users/{user_id}/passkeys/{passkey_id}`: an operator removes one passkey, for
 * somebody who lost the device it lived on (docs/design/passkeys.md §9).
 *
 * One at a time, so the operator sees what they remove; the recovery codes and the authenticator
 * app are `DELETE /api/v1/users/{user_id}/mfa`. A passkey that is not this account's is as absent
 * as one that does not exist. The removal is recorded with the request's caller as its actor.
 */
final readonly class RemoveUserPasskey
{
    public function __construct(
        private UserRepository $users,
        private PasskeyRepository $passkeys,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound When there is no such account, or no such passkey on it.
     */
    public function __invoke(UserId $userId, string $passkeyId): void
    {
        $this->users->find($userId) ?? throw NotFound::of('user');
        try {
            $passkey = $this->passkeys->one(PasskeyId::fromString($passkeyId));
        } catch (InvalidValue) {
            $passkey = null;
        }
        if ($passkey === null || ! $passkey->userId->equals($userId)) {
            throw NotFound::of('passkey');
        }

        $this->passkeys->delete($passkey->id);
        $this->events->dispatch(new PasskeyRemoved($passkey->userId, $passkey->id, $passkey->name, false));
    }
}
