<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Import;

/**
 * Why an account was not imported: a stable code and what is wrong, naming the field at fault, never
 * its value. A refusal is final: the same account would be refused again.
 */
final readonly class ImportRefusal
{
    /**
     * @param non-empty-string $error  `invalid_connection`, `invalid_json`, `invalid_field`, `unsupported_hash`
     *                                or `already_exists`.
     * @param non-empty-string $detail
     */
    public function __construct(
        public string $error,
        public string $detail,
    ) {
    }
}
