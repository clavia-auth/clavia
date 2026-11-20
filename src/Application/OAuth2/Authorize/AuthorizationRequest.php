<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\OAuth2\RequestParameters;

/**
 * A request to the authorization endpoint (RFC 6749 §4.1.1), as received.
 */
final readonly class AuthorizationRequest
{
    /**
     * @param RequestParameters $parameters    Query and body parameters together, unvalidated.
     * @param string            $requestTarget This request's own path and query string — where the
     *                                         browser returns to after signing in.
     * @param EndUser|null      $endUser       Who is signed in, when somebody is.
     */
    public function __construct(
        public RequestParameters $parameters,
        public string $requestTarget,
        public ?EndUser $endUser,
    ) {
    }
}
