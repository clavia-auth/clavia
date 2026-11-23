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
 * The person is signed in, but less strongly than the request asks: send the browser to the
 * second-factor page, where they give one more factor and come back with their session
 * raised (docs/design/mfa-policies.md §5.2).
 */
final readonly class StepUpRequired implements AuthorizationOutcome
{
    /**
     * @param non-empty-string $challenge The step-up challenge's handle, for the second-factor cookie.
     */
    public function __construct(public string $challenge)
    {
    }
}
