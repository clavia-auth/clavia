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
 * The request is valid and the person is signed in, but it has to be put to them first:
 * send the browser to the consent screen.
 */
final readonly class ConsentRequired implements AuthorizationOutcome
{
    /**
     * @param non-empty-string $consentState The opaque handle under which this request is on hold.
     */
    public function __construct(public string $consentState)
    {
    }
}
