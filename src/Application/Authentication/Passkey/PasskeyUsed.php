<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Passkey\Passkey;

/**
 * A passkey answered a ceremony: verified, its counter grown, its use recorded.
 */
final readonly class PasskeyUsed
{
    public function __construct(
        public Passkey $passkey,
        public bool $userVerified,
    ) {
    }

    /**
     * What it adds to `amr` (RFC 8176 §2).
     *
     * @return list<AuthenticationMethod>
     */
    public function methods(): array
    {
        return $this->passkey->authenticationMethods($this->userVerified);
    }
}
