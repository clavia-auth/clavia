<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

/**
 * The errors of the registration endpoint (RFC 7591 §3.2.2).
 */
enum RegistrationErrorCode: string
{
    /** A redirect URI (or a post-logout one) this server does not accept. */
    case InvalidRedirectUri = 'invalid_redirect_uri';

    /** Any other field: its value, its type, or its agreement with another field. */
    case InvalidClientMetadata = 'invalid_client_metadata';

    /** A software statement: this server has no publisher to check one against. */
    case InvalidSoftwareStatement = 'invalid_software_statement';
}
