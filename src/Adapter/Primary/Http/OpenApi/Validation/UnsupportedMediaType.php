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
 * The body is of a media type the operation does not take, has none, or declares a
 * charset JSON cannot have (RFC 8259 §8.1: UTF-8).
 */
final class UnsupportedMediaType extends RequestRejected
{
}
