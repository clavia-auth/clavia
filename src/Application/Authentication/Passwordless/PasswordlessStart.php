<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

/**
 * Someone asking on the login page for a code or a link to be sent to an address.
 */
final readonly class PasswordlessStart
{
    /**
     * @param string      $mode          `code` or `link`, as submitted.
     * @param string      $clientAddress Where the request came from, for the send limit.
     * @param string|null $loginState    The opaque handle of the pending authorization request, if any.
     */
    public function __construct(
        public string $email,
        public string $mode,
        public string $clientAddress,
        #[\SensitiveParameter] public ?string $loginState = null,
    ) {
    }
}
