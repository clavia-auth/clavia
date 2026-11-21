<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc\Event;

use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A new signing key took over; the one it replaced, if any, stays published for its grace.
 */
final readonly class SigningKeyRotated implements DomainEvent
{
    public function __construct(
        public SigningKey $active,
        public ?SigningKey $retired,
    ) {
    }
}
