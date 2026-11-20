<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Logout;

/**
 * A request at the end-session endpoint (OpenID Connect RP-Initiated Logout 1.0 §2),
 * and what the browser holds.
 */
final readonly class EndSessionRequest
{
    /**
     * @param string|null $idTokenHint           An ID token this server issued, proving who asks.
     * @param string|null $clientId              The application asking, when it sends no hint.
     * @param string|null $postLogoutRedirectUri Where the application asks to be sent back.
     * @param string|null $state                 Returned to the application with the browser.
     * @param bool        $confirmed             The person confirmed on this server's own page.
     * @param string|null $sessionId             The identifier the browser's session cookie carries.
     */
    public function __construct(
        #[\SensitiveParameter] public ?string $idTokenHint,
        public ?string $clientId,
        public ?string $postLogoutRedirectUri,
        public ?string $state,
        public bool $confirmed,
        #[\SensitiveParameter] public ?string $sessionId,
    ) {
    }
}
