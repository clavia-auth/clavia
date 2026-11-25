<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Port\OutboundUrls;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/** An endpoint's URL, held to the policy every URL this server sends to on an operator's say-so is. */
final readonly class WebhookUrl
{
    private function __construct()
    {
    }

    /** @throws InvalidValue With the reason's category, never the address it resolved to. */
    public static function checked(OutboundUrls $outbound, string $url): Url
    {
        $refusal = $outbound->refusal($url, 'webhook endpoint');
        if ($refusal !== null) {
            throw new InvalidValue($refusal);
        }

        return Url::fromString($url);
    }
}
