<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\BackChannelLogoutDelivery;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Url;

/**
 * Keeps every logout token it is asked to deliver, instead of posting it.
 */
final class RecordingBackChannelDelivery implements BackChannelLogoutDelivery
{
    /** @var list<array{client: string, uri: string, token: string}> In the order delivered. */
    public private(set) array $delivered = [];

    #[\Override]
    public function deliver(ClientId $client, Url $uri, #[\SensitiveParameter] string $logoutToken): void
    {
        $this->delivered[] = ['client' => $client->value, 'uri' => $uri->value, 'token' => $logoutToken];
    }
}
