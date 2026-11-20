<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Identity\UserId;

/**
 * The person on whose behalf a request is being made: the resource owner, as far as
 * the primary adapter could establish.
 *
 * The authorization endpoint cannot issue a code until it knows *which* user is
 * granting it; this is that answer, so the endpoint never has to know how
 * authentication happened.
 */
final readonly class EndUser
{
    /**
     * @param Session|null $session The browser session that established who this is; null when
     *                              something else did (the development auto-login). Later steps read
     *                              when and how the person authenticated from it (`auth_time`, `amr`).
     */
    public function __construct(
        public UserId $userId,
        public ?Session $session = null,
    ) {
    }
}
