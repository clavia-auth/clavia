<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Dpop;

/**
 * Why a DPoP proof is not good for the request it came with (RFC 9449 §4.3). For the log: the
 * client is told `invalid_dpop_proof` whatever the reason, or `use_dpop_nonce` for a nonce.
 */
enum DpopRefusal: string
{
    case Malformed = 'malformed';
    case WrongMethod = 'wrong_method';
    case WrongUrl = 'wrong_url';
    case TooOld = 'too_old';
    case FromTheFuture = 'from_the_future';
    case NonceNeeded = 'nonce_needed';
    case WrongAccessToken = 'wrong_access_token';
    case WrongKey = 'wrong_key';
    case Replayed = 'replayed';
}
