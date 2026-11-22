<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

/**
 * The form of the access tokens issued for an API.
 *
 * - **Opaque** (the default): a random string that means nothing outside this server. The
 *   API asks what it stands for at the introspection endpoint (RFC 7662), and so learns of
 *   a revocation the instant it happens.
 * - **JWT**: a signed JSON Web Token in the profile of RFC 9068 (`typ: at+jwt`), which the
 *   API validates on its own against the published keys, with no call to this server. The
 *   price is revocation: a JWT stays valid at the API until it expires, whatever this server
 *   records, so the access token lifetime is the longest a revoked token goes on working
 *   there. This server still records the token and honours its revocation everywhere it is
 *   presented to it (introspection, userinfo, the Management API).
 *
 * A token for no API at all — a sign-in asking only for OpenID Connect scopes — is always
 * opaque: RFC 9068 §2.2 requires an `aud`, and userinfo is the only place it opens.
 */
enum AccessTokenFormat: string
{
    case Opaque = 'opaque';
    case Jwt = 'jwt';
}
