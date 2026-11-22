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
 * The reset form cannot be used here: the application signs nobody in with a password, or
 * this deployment cannot send mail. Never an answer about an address.
 */
final readonly class ResetUnavailable
{
}
