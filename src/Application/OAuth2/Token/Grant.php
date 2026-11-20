<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * One way of obtaining a token at the token endpoint: one `grant_type`.
 */
interface Grant
{
    public function type(): GrantType;

    /**
     * How a client may authenticate when using this grant.
     *
     * @return list<ClientAuthMethod>
     */
    public function acceptedAuthMethods(): array;

    /**
     * Issue a token to an already-authenticated client that is registered for this grant.
     *
     * @throws OAuth2Error
     */
    public function issue(RequestParameters $parameters, Client $client): IssuedToken;
}
