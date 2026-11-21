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
 * The first signing key was generated: tokens are signed with it from now on.
 */
final readonly class SigningKeyCreated implements DomainEvent
{
    public function __construct(
        public SigningKey $key,
    ) {
    }
}
