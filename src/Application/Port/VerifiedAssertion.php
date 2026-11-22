<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * What a verified authentication response says: the counter and backup state to record on the
 * passkey ({@see \Clavia\Domain\Authentication\Passkey\Passkey::recordUse()}), and whether the
 * authenticator verified the person.
 *
 * The signature, the challenge, the origin, the site and the account have all been checked; the
 * counter has not: whether it grew is the passkey's rule, and its refusal an audit event.
 */
final readonly class VerifiedAssertion
{
    /**
     * @param bool $userVerified Whether the authenticator verified the person (the UV flag),
     *                           which decides whether `mfa` may be claimed.
     */
    public function __construct(
        public int $signCount,
        public bool $backupEligible,
        public bool $backedUp,
        public bool $userVerified,
    ) {
    }
}
