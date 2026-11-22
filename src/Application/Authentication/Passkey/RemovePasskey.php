<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\Event\PasskeyRemoved;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;

/**
 * Remove one of the session's own passkeys, within the re-authentication window.
 *
 * A person cannot remove their last way in (docs/design/passkeys.md §6.4): a passkey signs in by
 * itself, so the last one of an account in a pool, with no password and no identity at another
 * provider, is the account's only way in, and is refused. Recovery codes do not count: they
 * answer a second factor, after a first one.
 */
final readonly class RemovePasskey
{
    public function __construct(
        private PasskeyRepository $passkeys,
        private UserRepository $users,
        private ConnectionRepository $connections,
        private ExternalIdentityRepository $identities,
        private DomainEvents $events,
        private RecentSignIn $recentSignIn,
    ) {
    }

    public function __invoke(Session $session, string $passkeyId): PasskeyChange|SignInAgain
    {
        if (! $this->recentSignIn->allows($session)) {
            return new SignInAgain();
        }
        $passkey = OwnPasskey::find($this->passkeys, $session, $passkeyId);
        if ($passkey === null) {
            return PasskeyChange::NotFound;
        }
        if ($this->isTheOnlyWayIn($passkey)) {
            return PasskeyChange::LastWayIn;
        }
        $this->passkeys->delete($passkey->id);
        $this->events->dispatch(new PasskeyRemoved($passkey->userId, $passkey->id, $passkey->name, true));

        return PasskeyChange::Done;
    }

    private function isTheOnlyWayIn(Passkey $passkey): bool
    {
        $user = $this->users->find($passkey->userId);
        if ($user === null || $user->passwordHash() !== null || $this->passkeys->countOf($user->id) > 1) {
            return false;
        }

        // An external connection's account signs in through its provider, and a passwordless one
        // by email: only a pool's account can be left with nothing.
        return ($this->connections->find($user->connection)?->isDatabase() ?? false)
            && $this->identities->ofUser($user->id) === [];
    }
}
