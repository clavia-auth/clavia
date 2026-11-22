<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\Passkey;

/**
 * A passkey did not answer a ceremony, and why — with the passkey, when it is known.
 */
final readonly class PasskeyNotUsed
{
    public function __construct(
        public PasskeyRefusal $reason,
        public ?Passkey $passkey = null,
    ) {
    }
}
