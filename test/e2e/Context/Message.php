<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

/** A mail the stack sent, as Mailpit kept it. */
final readonly class Message
{
    public function __construct(public string $from, public string $subject, public string $text)
    {
    }
}
