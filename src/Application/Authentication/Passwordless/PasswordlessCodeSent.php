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
 * A code is on its way. The browser that asked holds the challenge's handle — the only
 * thing the code answers to — and is shown where to type it.
 */
final readonly class PasswordlessCodeSent
{
    /**
     * @param non-empty-string $handle The challenge's handle, to hand to this browser once.
     */
    public function __construct(
        #[\SensitiveParameter] public string $handle,
        public PasswordlessPrompt $prompt,
    ) {
    }
}
