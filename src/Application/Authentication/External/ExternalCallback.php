<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

/**
 * What the provider's redirect brought back, and what the browser holds.
 */
final readonly class ExternalCallback
{
    /**
     * @param string      $provider         The provider named by the callback's path.
     * @param string|null $code             The authorization code, if the provider sent one.
     * @param string|null $state            The `state` the provider echoed.
     * @param bool        $errorReported    Whether the provider sent an `error` (RFC 6749 §4.1.2.1) —
     *                                      its value is never read.
     * @param string|null $browserState     The `state` handle the browser's cookie carries.
     * @param string|null $currentSessionId The session identifier the browser presented, if any.
     */
    public function __construct(
        public string $provider,
        #[\SensitiveParameter] public ?string $code,
        #[\SensitiveParameter] public ?string $state,
        public bool $errorReported,
        #[\SensitiveParameter] public ?string $browserState,
        #[\SensitiveParameter] public ?string $currentSessionId,
    ) {
    }
}
