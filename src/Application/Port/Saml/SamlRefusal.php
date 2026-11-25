<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

/**
 * Why a response was refused. The person sees one answer whatever this is (§7, "No padding oracle");
 * the log keeps the category, never what the identity provider wrote.
 */
enum SamlRefusal: string
{
    /** Not a readable response: too large, not base64, not XML, a `DOCTYPE`, a comment, two assertions. */
    case Xml = 'xml';

    /** The assertion is not signed, or not by a certificate of the connection, or with a weak algorithm. */
    case Signature = 'signature';

    /** An encrypted assertion, which needs this server's keys (slice 6), or one that does not decrypt. */
    case Decryption = 'decryption';

    /** Another identity provider's. */
    case Issuer = 'issuer';

    /** For another service provider's endpoint: `Destination` or `Recipient`. */
    case Destination = 'destination';

    /** For another service provider: `Audience`. */
    case Audience = 'audience';

    /** Not an answer to this request: `InResponseTo`. */
    case InResponseTo = 'in_response_to';

    /** Outside its time windows, past the clock skew allowed. */
    case Expired = 'expired';

    /** The identity provider says the sign-in failed. */
    case Status = 'status';

    /** No usable subject: transient, missing, or no bearer confirmation or authentication statement. */
    case Subject = 'subject';
}
