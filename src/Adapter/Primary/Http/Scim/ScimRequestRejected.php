<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use RuntimeException;

/** A request the SCIM surface refuses before any use case runs: its body, or a query parameter. */
final class ScimRequestRejected extends RuntimeException
{
    /**
     * @param string      $detail   The rule broken, never a value sent.
     * @param string|null $scimType RFC 7644 §3.12's, for a `400`.
     */
    public function __construct(
        public readonly int $status,
        string $detail,
        public readonly ?string $scimType = null,
    ) {
        parent::__construct($detail);
    }
}
