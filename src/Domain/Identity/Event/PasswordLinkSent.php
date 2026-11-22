<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Event;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A link to choose a password was mailed to an account at an operator's request: an
 * invitation when the account has no password yet, a reset when it has one.
 *
 * Nothing about the link itself is recorded; it is a secret, and only its digest is kept.
 */
final readonly class PasswordLinkSent implements DomainEvent
{
    public function __construct(
        public UserId $userId,
        public bool $invitation,
    ) {
    }
}
