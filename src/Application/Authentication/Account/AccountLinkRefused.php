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
 * A link that cannot be followed: unknown, spent, expired, meant for something else, or no
 * longer matching its account. One answer for all of them.
 */
final readonly class AccountLinkRefused
{
}
