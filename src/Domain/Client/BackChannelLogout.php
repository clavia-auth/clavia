<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * Where a client wants to be told that a session it signed in through has ended, and
 * whether it needs that session named (OIDC Back-Channel Logout 1.0 §2.2).
 *
 * This server posts to the address on its own account, server to server, so it is
 * https and nothing else; whether it may point where it points — not at this server's
 * own network — is checked by the outbound policy, at registration and again on every
 * send, because what a name resolves to can change in between.
 */
final readonly class BackChannelLogout
{
    /**
     * @param bool $sessionRequired `backchannel_logout_session_required`: the client needs `sid` in
     *                              the logout token. This server always sends it, so this only
     *                              records what the client asked for.
     *
     * @throws InvalidValue When the URI is not https, or has a fragment (§2.2).
     */
    public function __construct(
        public Url $uri,
        public bool $sessionRequired = false,
    ) {
        if (! $uri->isHttps()) {
            throw new InvalidValue('A back-channel logout URI must be an https URL.');
        }
        if ($uri->hasFragment()) {
            throw new InvalidValue('A back-channel logout URI must not contain a fragment.');
        }
    }

    public function equals(self $other): bool
    {
        return $this->uri->equals($other->uri) && $this->sessionRequired === $other->sessionRequired;
    }
}
