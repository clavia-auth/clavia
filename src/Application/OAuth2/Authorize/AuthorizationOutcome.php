<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

/**
 * What the authorization endpoint decided: {@see CodeIssued}, {@see RequestRefused}
 * or {@see LoginRequired}.
 *
 * A request whose client or redirect URI cannot be trusted has no outcome at all — it
 * raises an {@see \Clavia\Domain\OAuth2\OAuth2Error}, which must be answered locally
 * and never by redirecting.
 */
interface AuthorizationOutcome
{
}
