<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A passkey presented a signature counter that did not grow, so its authenticator may have
 * been cloned (WebAuthn Level 3 §6.1.3). The sign-in was refused; the passkey stays, for its
 * holder or an operator to look at.
 */
final readonly class PasskeyCounterRegressed implements DomainEvent
{
    public function __construct(
        public UserId $userId,
        public PasskeyId $passkeyId,
        public PasskeyName $name,
        public int $storedCounter,
        public int $presentedCounter,
    ) {
    }
}
