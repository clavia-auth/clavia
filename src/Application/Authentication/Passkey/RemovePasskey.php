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
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Session;

/**
 * Remove one of the session's own passkeys, within the re-authentication window.
 *
 * In this phase a passkey is only ever a second factor, so removing one never takes away the way
 * into an account: the password, provider or email it signs in with stays. Guarding the last way
 * in (docs/design/passkeys.md §6.4) comes with signing in by passkey.
 */
final readonly class RemovePasskey
{
    public function __construct(
        private PasskeyRepository $passkeys,
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
        $this->passkeys->delete($passkey->id);
        $this->events->dispatch(new PasskeyRemoved($passkey->userId, $passkey->id, $passkey->name, true));

        return PasskeyChange::Done;
    }
}
