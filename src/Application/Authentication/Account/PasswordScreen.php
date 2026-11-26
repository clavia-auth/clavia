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
     * For a caller that reports refusals in its own words (the Management API's `422`).
     *
     * @return non-empty-string
     *
     * @throws InvalidValue When the policy refuses the password, or it is known to have leaked.
     */
    public function accept(#[\SensitiveParameter] string $password): string
    {
        $accepted = PasswordPolicy::accept($password);
        if ($this->breached($accepted)) {
            throw new InvalidValue(self::BREACHED);
        }

        return $accepted;
    }

    /**
     * For a sign-in page, which words a refusal in the person's language: the password accepted, or why
     * not.
     *
     * @return non-empty-string|PasswordRefusal
     */
    public function screen(#[\SensitiveParameter] string $password): string|PasswordRefusal
    {
        try {
            $accepted = PasswordPolicy::accept($password);
        } catch (InvalidValue) {
            return PasswordRefusal::Policy;
        }

        return $this->breached($accepted) ? PasswordRefusal::Breached : $accepted;
    }

    private function breached(#[\SensitiveParameter] string $password): bool
    {
        try {
            return $this->breaches->isBreached($password);
        } catch (BreachCheckUnavailable) {
            // Fail open (see above).
            return false;
        }
    }
}
