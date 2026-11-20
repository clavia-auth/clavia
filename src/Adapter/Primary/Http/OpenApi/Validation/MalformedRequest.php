<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

/**
 * The request cannot be read as the document's: a body that is not valid JSON, a value
 * that is not valid percent-encoded UTF-8, or a single-valued parameter sent more than
 * once (RFC 6749 §3.1's rule, generalised: which copy was meant is not guessable).
 */
final class MalformedRequest extends RequestRejected
{
}
