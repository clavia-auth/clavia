<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Domain\Shared\Language;

/**
 * What the sign-up form posted.
 */
final readonly class SignUpRequest
{
    /**
     * @param string|null   $loginState       The login page's handle the form carried.
     * @param string        $clientAddress    Where the request came from (`REMOTE_ADDR`).
     * @param string|null   $currentSessionId The session the browser already holds, if any.
     * @param Language|null $language         The page's language: what the mail it causes is in.
     */
    public function __construct(
        public string $email,
        #[\SensitiveParameter] public string $password,
        #[\SensitiveParameter] public ?string $loginState,
        public string $clientAddress,
        #[\SensitiveParameter] public ?string $currentSessionId,
        public ?Language $language = null,
    ) {
    }
}
