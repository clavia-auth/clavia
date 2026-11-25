<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Webhooks;

use Clavia\Application\Audit\AuditEventDocument;
use Clavia\Application\Management\Webhooks\WebhookSecrets;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\WebhookSender;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Webhook\DeliveryFailure;
use Clavia\Domain\Webhook\StandardWebhookSignature;
use Clavia\Domain\Webhook\WebhookDelivery;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use Clavia\Domain\Webhook\WebhookSecret;

/**
 * `clavia webhooks:deliver`, every minute (docs/design/webhooks.md §5.3): claims the endpoints with
 * deliveries due, and sends each one's deliveries in order, one at a time, so a receiver never has
 * two in flight. Each is the audit event as the Management API renders it, in a Standard Webhooks
 * envelope, signed with the endpoint's secret (and the previous one during a rotation).
 *
 * A failure is retried on the {@see \Clavia\Domain\Webhook\RetrySchedule} and stops that endpoint
 * for this run, so the later deliveries wait their turn behind it. A switched-off endpoint's
 * deliveries, and those whose event was purged, are abandoned. The run stops after
 * {@see BUDGET_SECONDS}, leaving the rest to the next minute, then deletes the deliveries that
 * ended {@see RETENTION_DAYS} days ago.
 */
final readonly class DeliverWebhooks
{
    public const int BUDGET_SECONDS = 50;
    public const int CLAIM_SECONDS = 30;
    public const int RETENTION_DAYS = 7;
    private const int ENDPOINTS_PER_CLAIM = 10;
    private const int DELIVERIES_PER_ENDPOINT = 50;

    private const int JSON = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private WebhookDeliveryRepository $deliveries,
        private AuditLog $log,
        private SecretCipher $cipher,
        private WebhookSender $sender,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    public function __invoke(): WebhooksDelivered
    {
        $deadline = $this->clock->now()->modify(sprintf('+%d seconds', self::BUDGET_SECONDS));
        $counts = ['succeeded' => 0, 'failed' => 0, 'abandoned' => 0];
        $done = [];

        while ($this->clock->now() < $deadline) {
            $now = $this->clock->now();
            $claimed = array_values(array_filter(
                $this->deliveries->claimEndpoints(
                    $now,
                    $now->modify(sprintf('+%d seconds', self::CLAIM_SECONDS)),
                    self::ENDPOINTS_PER_CLAIM,
                ),
                // An endpoint is taken once a run: what is due again waits for the next one.
                static fn (WebhookEndpointId $id): bool => ! in_array($id->value, $done, true),
            ));
            if ($claimed === []) {
                break;
            }
            foreach ($claimed as $id) {
                $done[] = $id->value;
                try {
                    $this->deliverTo($id, $deadline, $counts);
                } finally {
                    $this->deliveries->release($id);
                }
            }
        }

        $purged = $this->deliveries->purgeEndedBefore(
            $this->clock->now()->modify(sprintf('-%d days', self::RETENTION_DAYS)),
        );

        return new WebhooksDelivered($counts['succeeded'], $counts['failed'], $counts['abandoned'], $purged);
    }

    /** @param array{succeeded: int, failed: int, abandoned: int} $counts */
    private function deliverTo(WebhookEndpointId $id, \DateTimeImmutable $deadline, array &$counts): void
    {
        $endpoint = $this->endpoints->find($id);
        foreach ($this->deliveries->due($id, $this->clock->now(), self::DELIVERIES_PER_ENDPOINT) as $delivery) {
            if ($this->clock->now() >= $deadline) {
                return;
            }
            $event = $this->log->find($delivery->auditEventId);
            if ($endpoint === null || ! $endpoint->isEnabled || $event === null) {
                $why = $event === null ? DeliveryFailure::EventPurged : DeliveryFailure::Disabled;
                $this->deliveries->save($delivery->abandoned($why, $this->clock->now()));
                ++$counts['abandoned'];
                continue;
            }

            $attempted = $this->attempt($endpoint, $delivery, $event);
            $this->deliveries->save($attempted);
            if ($attempted->lastFailure === null) {
                ++$counts['succeeded'];
                continue;
            }
            ++$counts[$attempted->endedAt === null ? 'failed' : 'abandoned'];

            // In order: the rest wait behind the one that failed.
            return;
        }
    }

    private function attempt(WebhookEndpoint $endpoint, WebhookDelivery $delivery, AuditEvent $event): WebhookDelivery
    {
        $now = $this->clock->now();
        $body = json_encode([
            'type' => $event->type->value,
            'timestamp' => $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\\TH:i:s.v\\Z'),
            'data' => AuditEventDocument::of($event),
        ], self::JSON);
        $messageId = $event->id->value;
        $timestamp = $now->getTimestamp();

        $outcome = $this->sender->send($endpoint->url, [
            'content-type' => 'application/json',
            'webhook-id' => $messageId,
            'webhook-timestamp' => (string) $timestamp,
            'webhook-signature' => StandardWebhookSignature::header(
                $messageId,
                $timestamp,
                $body,
                $this->secretsOf($endpoint, $now),
            ),
        ], $body);

        return $outcome->failure === null
            ? $delivery->succeeded((int) $outcome->statusCode, $outcome->durationMs, $this->clock->now())
            : $delivery->failed(
                $outcome->failure,
                $outcome->statusCode,
                $outcome->durationMs,
                $this->clock->now(),
                $this->random,
            );
    }

    /** @return non-empty-list<WebhookSecret> The current secret, then the previous one while it lasts. */
    private function secretsOf(WebhookEndpoint $endpoint, \DateTimeImmutable $now): array
    {
        $context = WebhookSecrets::context($endpoint->id);
        $secrets = [WebhookSecret::unsealed($this->open($endpoint->sealedSecret, $context))];
        $previous = $endpoint->previousSecretAt($now);
        if ($previous !== null) {
            $secrets[] = WebhookSecret::unsealed($this->open($previous, $context));
        }

        return $secrets;
    }

    /** @return non-empty-string */
    private function open(string $sealed, string $context): string
    {
        $secret = $this->cipher->decrypt($sealed, $context);

        return $secret !== '' ? $secret : throw new \LogicException('A webhook secret opened to nothing.');
    }
}
