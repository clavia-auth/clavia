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
 * What became of an account link handed to {@see SendAccountLink}.
 *
 * Callers that must not say whether an address has an account fold the three into one
 * answer; an operator, who is authenticated and entitled to know, does not.
 */
enum Delivery
{
    /** The mail left, and the link is open. */
    case Sent;

    /** The account send limit stopped it: nothing was opened or sent. */
    case LimitReached;

    /** The mail could not be delivered, so the link was closed again. */
    case MailUnavailable;
}
