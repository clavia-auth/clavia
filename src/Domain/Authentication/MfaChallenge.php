<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;

/**
 * The half-finished sign-in between a correct first factor and a correct second one.
 *
 * A correct password is not a session once a second factor is enrolled. What the browser
 * holds instead, for a few minutes, is a handle to this: proof the first factor passed,
 * which authenticates nothing on its own. It carries what finishing needs — who is
 * signing in, where to go afterwards and for which application, how the first factor was
 * satisfied — and how many wrong second-factor answers it has already taken.
 */
final readonly class MfaChallenge
{
    /**
     * @param string                     $nextUrl     A local path, already validated by {@see LocalPath}.
     * @param list<AuthenticationMethod> $firstFactor
     * @param non-negative-int           $attempts    Wrong answers so far.
     */
    public function __construct(
        public UserId $userId,
        public string $nextUrl,
        public ?ClientId $clientId,
        public array $firstFactor,
        public int $attempts = 0,
    ) {
    }
}
