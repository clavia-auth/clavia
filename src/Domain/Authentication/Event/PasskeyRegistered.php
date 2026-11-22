<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A passkey was registered on an account by its holder.
 *
 * Nothing of the credential itself: not its id, not its key.
 */
final readonly class PasskeyRegistered implements DomainEvent
{
    /**
     * @param bool $synced Whether a credential manager backs it up across devices.
     */
    public function __construct(
        public UserId $userId,
        public PasskeyId $passkeyId,
        public PasskeyName $name,
        public bool $synced,
        public ?Aaguid $aaguid,
    ) {
    }
}
