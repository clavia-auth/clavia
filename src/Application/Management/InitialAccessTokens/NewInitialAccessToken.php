<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\InitialAccessTokens;

/**
 * What an operator asks for when issuing an initial access token.
 */
final readonly class NewInitialAccessToken
{
    /** Seven days: long enough to hand a token over and use it, short enough to forget about. */
    public const int DEFAULT_LIFETIME_SECONDS = 604_800;

    /**
     * @param string $description     Who it is for, 1 to 120 bytes: the token is never shown again.
     * @param int    $lifetimeSeconds A minute to ninety days.
     * @param int    $maxUses         How many clients it registers, 1 to 1000.
     */
    public function __construct(
        public string $description,
        public int $lifetimeSeconds = self::DEFAULT_LIFETIME_SECONDS,
        public int $maxUses = 1,
    ) {
    }
}
