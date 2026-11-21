<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

/**
 * The person allowed the request, and it is remembered: send the browser back to it.
 */
final readonly class ConsentGiven
{
    /**
     * @param string $resumeAt A local path: the authorization request, which now finds the consent
     *                         and issues the code.
     */
    public function __construct(public string $resumeAt)
    {
    }
}
