<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use RuntimeException;

/**
 * A parameter the contract could not describe precisely enough, read by the handler and found malformed:
 * a request the caller built wrong, so `400` (RFC 9110 §15.5.1), as for what the contract refuses
 * itself. The message names the parameter, never its value.
 */
final class MalformedParameter extends RuntimeException
{
    public function __construct(public readonly string $parameter, string $message)
    {
        parent::__construct($message);
    }
}
