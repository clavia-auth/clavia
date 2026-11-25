<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/** The endpoints, never a secret: twenty at most, so a plain list. */
final readonly class ReadWebhooks
{
    public function __construct(private WebhookEndpointRepository $endpoints)
    {
    }

    /** @return list<WebhookEndpoint> */
    public function all(): array
    {
        return $this->endpoints->all();
    }

    /** @throws NotFound */
    public function one(WebhookEndpointId $id): WebhookEndpoint
    {
        return $this->endpoints->find($id) ?? throw NotFound::of('webhook');
    }
}
