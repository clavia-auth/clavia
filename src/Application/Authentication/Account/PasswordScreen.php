<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Port\BreachCheckUnavailable;
use Clavia\Application\Port\BreachedPasswords;
use Clavia\Domain\Identity\PasswordPolicy;
use Clavia\Domain\Shared\InvalidValue;

/**
 * What a password must pass to be set on an account, wherever it is chosen: at sign-up,
 * at a reset, and when an operator sets one through the Management API.
 *
 * First the {@see PasswordPolicy} (length, bytes), then the breached-password corpus
 * (NIST SP 800-63B §5.1.1.2). A corpus that cannot be asked lets the password through:
 * the check is a defence in depth, and an outage of somebody else's service must not stop
 * people from signing up or recovering their account. The adapter logs the outage.
 */
final readonly class PasswordScreen
{
    public const string BREACHED = 'This password has appeared in a data breach. Choose another one.';

    public function __construct(private BreachedPasswords $breaches)
    {
    }

    /**
     * @return non-empty-string
     *
     * @throws InvalidValue When the policy refuses the password, or it is known to have leaked.
     */
    public function accept(#[\SensitiveParameter] string $password): string
    {
        $accepted = PasswordPolicy::accept($password);

        try {
            $breached = $this->breaches->isBreached($accepted);
        } catch (BreachCheckUnavailable) {
            // Fail open (see above).
            $breached = false;
        }
        if ($breached) {
            throw new InvalidValue(self::BREACHED);
        }

        return $accepted;
    }
}
