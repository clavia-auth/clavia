<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

/**
 * Why no link went out although the account could have one: a condition of the deployment,
 * not of the request, so the operator can try again later.
 */
enum PasswordLinkRefused
{
    /** The account send limit, per address or per client address, is reached. */
    case LimitReached;

    /** This deployment sends no mail, or the mail server did not take the message. */
    case MailUnavailable;
}
