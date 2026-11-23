<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

/**
 * The error codes of a resource server refusing a bearer token (RFC 6750 §3.1).
 */
enum BearerErrorCode: string
{
    /** The request is malformed: a broken `Authorization` header, a token sent twice. */
    case InvalidRequest = 'invalid_request';

    /** The token is unknown, expired, revoked, or names nobody who may still act. */
    case InvalidToken = 'invalid_token';

    /** The token is fine but was not granted the scope this resource needs. */
    case InsufficientScope = 'insufficient_scope';

    /**
     * The token is fine, but the person signed in less strongly than this resource needs
     * (RFC 9470 §3): the client asks for a new one with the `acr_values` the challenge names.
     */
    case InsufficientUserAuthentication = 'insufficient_user_authentication';
}
