<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Port\OutboundUrls;
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * A back-channel logout URI as an operator registers it: an absolute https URL with no
 * fragment, and one this server may post to — not at itself or its internal network.
 * Refused at registration so the operator hears about it then, rather than from a log
 * line on the day somebody signs out.
 */
final readonly class BackChannelLogoutRegistration
{
    public function __construct(private OutboundUrls $outbound)
    {
    }

    /**
     * @param string|null $uri Null for none: the client is not told.
     *
     * @throws InvalidValue
     */
    public function of(?string $uri, bool $sessionRequired): ?BackChannelLogout
    {
        if ($uri === null) {
            return null;
        }

        $backChannel = new BackChannelLogout(Url::fromString($uri), $sessionRequired);
        $refusal = $this->outbound->refusal($backChannel->uri->value, 'back-channel logout URI');
        if ($refusal !== null) {
            throw new InvalidValue($refusal);
        }

        return $backChannel;
    }
}
