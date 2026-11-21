<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Url;

/**
 * Posts a logout token to a client's back-channel logout URI (OIDC Back-Channel Logout
 * 1.0 §2.5), server to server.
 *
 * Never throws: a client that is down, refuses the token or lives where this server must
 * not post — the address is checked again at every send, as what a name resolves to can
 * change — is logged and given up on. Nothing is retried: the client's own session ends
 * on its own schedule, which is where it was before back-channel logout existed.
 */
interface BackChannelLogoutDelivery
{
    public function deliver(ClientId $client, Url $uri, #[\SensitiveParameter] string $logoutToken): void;
}
