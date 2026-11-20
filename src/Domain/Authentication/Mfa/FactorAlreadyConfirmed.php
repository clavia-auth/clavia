<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use DomainException;

/**
 * Enrollment was started over a factor that is already on. Replacing a working factor
 * goes through turning it off first — never as a side effect of visiting the set-up
 * page again.
 */
final class FactorAlreadyConfirmed extends DomainException
{
    public function __construct()
    {
        parent::__construct('Two-factor authentication is already on for this account.');
    }
}
