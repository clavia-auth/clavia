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
 * The request requires more than one factor and the person has none: send the browser to set
 * one up, holding the request behind a login state it comes back to
 * (docs/design/mfa-policies.md §5.3).
 */
final readonly class EnrolmentRequired implements AuthorizationOutcome
{
    /**
     * @param non-empty-string $loginState The handle under which the request is held.
     */
    public function __construct(public string $loginState)
    {
    }
}
