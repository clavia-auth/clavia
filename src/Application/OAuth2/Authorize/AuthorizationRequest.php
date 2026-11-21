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
     * @param RequestParameters $parameters Query and body parameters together, unvalidated.
     * @param string            $endpoint   The path the request arrived at.
     * @param EndUser|null      $endUser    Who is signed in, when somebody is.
     */
    public function __construct(
        public RequestParameters $parameters,
        public string $endpoint,
        public ?EndUser $endUser,
    ) {
    }

    /**
     * Where to send the browser to make this request again — after it signed in, or
     * consented — as a `GET` carrying every parameter in its query, whichever method
     * brought it here: a request posted to the endpoint is resumed with all of it.
     */
    public function resumption(RequestParameters $parameters): string
    {
        $query = $parameters->toQueryString();

        return $query === '' ? $this->endpoint : $this->endpoint . '?' . $query;
    }
}
