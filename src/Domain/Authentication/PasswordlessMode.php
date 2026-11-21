<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Domain\Authentication;

/**
 * The two shapes of the same proof — control of a mailbox — that a person chooses between
 * on the login page.
 */
enum PasswordlessMode: string
{
    /**
     * Six digits typed back into the browser that asked. The code is worthless to anyone
     * who only sees the email: it answers a challenge only that browser holds.
     */
    case Code = 'code';

    /**
     * A long single-use secret in a link, usable from any browser — "open this on your
     * phone" is the point of a link.
     */
    case Link = 'link';
}
