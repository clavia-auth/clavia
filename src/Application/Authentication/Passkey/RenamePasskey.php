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
use Clavia\Domain\Authentication\Event\PasskeyRenamed;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Give one of the session's own passkeys another name, within the re-authentication window.
 */
final readonly class RenamePasskey
{
    public function __construct(
        private PasskeyRepository $passkeys,
        private DomainEvents $events,
        private RecentSignIn $recentSignIn,
    ) {
    }

    public function __invoke(Session $session, string $passkeyId, string $name): PasskeyChange|SignInAgain
    {
        if (! $this->recentSignIn->allows($session)) {
            return new SignInAgain();
        }
        $passkey = OwnPasskey::find($this->passkeys, $session, $passkeyId);
        if ($passkey === null) {
            return PasskeyChange::NotFound;
        }
        try {
            $passkey->rename(PasskeyName::fromString($name));
        } catch (InvalidValue) {
            return PasskeyChange::InvalidName;
        }
        $this->passkeys->save($passkey);
        $this->events->dispatch(new PasskeyRenamed($passkey->userId, $passkey->id, $passkey->name));

        return PasskeyChange::Done;
    }
}
