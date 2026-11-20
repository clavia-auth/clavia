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
 * How a sign-in was authenticated, as an Authentication Method Reference (RFC 8176 §2).
 *
 * Recorded on the session when it is established and never recomputed: it describes an
 * event. The values are the registered ones relying parties look for in the `amr` claim.
 */
enum AuthenticationMethod: string
{
    /** A password was typed on the login page. */
    case Password = 'pwd';
}
