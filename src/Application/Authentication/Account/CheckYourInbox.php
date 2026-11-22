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
 * The answer that something was mailed — or, to anyone who must not learn whether an address
 * has an account, the answer that it may have been. Sign-up into a pool requiring a verified
 * address, and a reset request, both end here, whatever happened.
 */
final readonly class CheckYourInbox
{
    /**
     * @param non-empty-string $email The address the person typed, to say where to look.
     */
    public function __construct(
        public string $email,
    ) {
    }
}
