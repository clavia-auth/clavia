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
use Clavia\Domain\Client\ClientId;

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
    /** The same request, its parameters being `$parameters`: those it pushed (RFC 9126 §4). */
    public function withParameters(RequestParameters $parameters): self
    {
        return new self($parameters, $this->endpoint, $this->endUser);
    }

    /**
     * Where to send the browser to make a pushed request again: by reference, so its parameters
     * never travel in the browser's address bar (RFC 9126 §4).
     */
    public function byReference(ClientId $clientId, string $requestUri): string
    {
        return $this->endpoint . '?' . http_build_query(
            ['client_id' => $clientId->value, 'request_uri' => $requestUri],
            '',
            '&',
            PHP_QUERY_RFC3986,
        );
    }

    public function resumption(RequestParameters $parameters): string
    {
        $query = $parameters->toQueryString();

        return $query === '' ? $this->endpoint : $this->endpoint . '?' . $query;
    }
}
