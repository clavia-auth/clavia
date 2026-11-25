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
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Webhook\WebhookDelivery;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/**
 * An endpoint's delivery log, newest first (docs/design/webhooks.md §5.4): what was sent, how often,
 * and what came back, as a status code and a category; never a body, which is not kept.
 */
final readonly class ReadWebhookDeliveries
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private WebhookDeliveryRepository $deliveries,
    ) {
    }

    /**
     * @return Page<WebhookDelivery>
     *
     * @throws NotFound
     */
    public function __invoke(WebhookEndpointId $id, PageRequest $request): Page
    {
        $this->endpoints->find($id) ?? throw NotFound::of('webhook');

        return $this->deliveries->page($id, $request);
    }
}
