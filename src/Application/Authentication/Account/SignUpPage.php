<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

/**
 * The facts the sign-up page is rendered from.
 */
final readonly class SignUpPage
{
    /**
     * @param bool         $available             Whether the form may be shown at all.
     * @param bool         $requiresVerification  Whether the account must prove its address first.
     * @param list<string> $formOrigins           Where a sign-up that signs in at once may end: the
     *                                            application's redirect origins.
     */
    public function __construct(
        public bool $available,
        public bool $requiresVerification,
        public array $formOrigins,
    ) {
    }
}
