<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization;

use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;

/**
 * Which API a caller of the Authorization API speaks for (docs/design/fine-grained-authorization.md
 * §2): the one listing its client, with authorization switched on. Every question and every write is
 * answered from that API's store and model alone, so an API can neither ask about nor write into
 * another's resources.
 */
final readonly class SpokenForApi
{
    public function __construct(private ResourceServerRepository $resourceServers)
    {
    }

    /**
     * @return array{ResourceServer, AuthorizationSettings}
     *
     * @throws SpeaksForNoApi
     */
    public function of(ClientId $client): array
    {
        $api = $this->resourceServers->spokenForBy($client);
        $settings = $api?->authorization;
        if ($api === null || $settings === null || ! $settings->enabled) {
            throw new SpeaksForNoApi();
        }

        return [$api, $settings];
    }
}
