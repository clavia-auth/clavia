<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\OutboundUrls;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\Event\WebhookCreated;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/**
 * `POST /api/v1/webhooks`: register an endpoint (docs/design/webhooks.md §5.1). Its URL is held to
 * `OutboundUrlPolicy` now, as the operator should hear of a refusal now (and again at every send);
 * its event types must exist; there are at most twenty. The answer carries the secret, once.
 */
final readonly class RegisterWebhook
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private WebhookSecrets $secrets,
        private OutboundUrls $outbound,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param list<string> $events
     *
     * @throws InvalidValue When the URL, the description or an event type is refused.
     * @throws Conflict     When twenty endpoints exist already.
     */
    public function __invoke(string $url, string $description, array $events): WebhookWithSecret
    {
        $target = WebhookUrl::checked($this->outbound, $url);
        $filter = EventFilter::fromStrings($events);

        /** @var WebhookWithSecret */
        return $this->transactions->transactional(function () use ($target, $description, $filter): WebhookWithSecret {
            if ($this->endpoints->count() >= WebhookEndpoint::MAX_ENDPOINTS) {
                throw new Conflict(sprintf('At most %d webhook endpoints.', WebhookEndpoint::MAX_ENDPOINTS));
            }
            $id = WebhookEndpointId::generate($this->random);
            $secret = $this->secrets->generate();
            $endpoint = WebhookEndpoint::register(
                $id,
                $target,
                $description,
                $filter,
                $this->secrets->seal($id, $secret),
                $this->clock->now(),
            );
            $this->endpoints->save($endpoint);
            $this->events->dispatch(new WebhookCreated($endpoint));

            return new WebhookWithSecret($endpoint, $secret);
        });
    }
}
