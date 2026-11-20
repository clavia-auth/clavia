<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

/**
 * One RFC 9457 problem document: a status, what went wrong for a person to read, and —
 * for a request the contract refused — where.
 *
 * `type` is always `about:blank` (RFC 9457 §4.2.1): the HTTP status says everything a
 * program needs to branch on, and the title is its phrase.
 */
final readonly class Problem
{
    /**
     * @param list<array{pointer?: string, parameter?: string, detail: string}> $errors
     */
    public function __construct(
        public int $status,
        public string $detail,
        public array $errors = [],
    ) {
    }
}
