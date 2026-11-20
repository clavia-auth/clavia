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
 * The registered OAuth 2.0 error codes this server answers with
 * (RFC 6749 §4.1.2.1 for the authorization endpoint, §5.2 for the token endpoint).
 */
enum ErrorCode: string
{
    /** A required parameter is missing, repeated, or malformed. */
    case InvalidRequest = 'invalid_request';

    /** Client authentication failed, or the client is unknown. */
    case InvalidClient = 'invalid_client';

    /** The code (or other grant) is invalid, expired, revoked, spent, or was issued to someone else. */
    case InvalidGrant = 'invalid_grant';

    /** The client is not registered for what it asked. */
    case UnauthorizedClient = 'unauthorized_client';

    /** The token endpoint does not offer this `grant_type`. */
    case UnsupportedGrantType = 'unsupported_grant_type';

    /** The authorization endpoint does not offer this `response_type`. */
    case UnsupportedResponseType = 'unsupported_response_type';

    /** The requested scope is unknown, malformed, or more than may be granted. */
    case InvalidScope = 'invalid_scope';
}
