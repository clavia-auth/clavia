<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Webhook;

use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Webhook\DeliveryFailure;
use Clavia\Domain\Webhook\RetrySchedule;
use Clavia\Domain\Webhook\StandardWebhookSignature;
use Clavia\Domain\Webhook\WebhookDelivery;
use Clavia\Domain\Webhook\WebhookDeliveryId;
use Clavia\Domain\Webhook\WebhookDeliveryStatus;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookSecret;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

/** Signing, retrying and ending a delivery (docs/design/webhooks.md §2, §5.3). */
final class WebhookDeliveryTest extends TestCase
{
    public function testTheSignatureIsTheStandardWebhooksOne(): void
    {
        // The Standard Webhooks specification's own example: its secret, id, timestamp and body.
        $secret = WebhookSecret::unsealed('whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw');

        self::assertSame(
            'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
            StandardWebhookSignature::header(
                'msg_p5jXN8AQM9LWM0D4loKWxJek',
                1614265330,
                '{"test": 2432232314}',
                [$secret],
            ),
        );
    }

    public function testDuringARotationBothSecretsSign(): void
    {
        $current = WebhookSecret::generate(new SeededRandomSource(1));
        $previous = WebhookSecret::generate(new SeededRandomSource(2));

        $header = StandardWebhookSignature::header('id', 1, '{}', [$current, $previous]);

        self::assertSame([
            StandardWebhookSignature::header('id', 1, '{}', [$current]),
            StandardWebhookSignature::header('id', 1, '{}', [$previous]),
        ], explode(' ', $header));
    }

    public function testTheScheduleSpreadsSevenRetriesOverADayAndAHalfThenStops(): void
    {
        $random = new SeededRandomSource(3);
        foreach (RetrySchedule::DELAYS as $i => $delay) {
            $actual = RetrySchedule::delayAfter($i + 1, $random);
            self::assertNotNull($actual);
            self::assertGreaterThanOrEqual($delay - intdiv($delay, 10), $actual);
            self::assertLessThanOrEqual($delay + intdiv($delay, 10), $actual);
        }
        self::assertNull(RetrySchedule::delayAfter(count(RetrySchedule::DELAYS) + 1, $random));
        self::assertSame(36_000 * 2 + 18_000 + 7200 + 1800 + 300 + 5, array_sum(RetrySchedule::DELAYS));
    }

    public function testAFailureIsRetriedUntilTheLastThenAbandoned(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $random = new SeededRandomSource(4);
        $delivery = self::pending($now);

        $delivery = $delivery->failed(DeliveryFailure::Status, 503, 40, $now, $random);
        self::assertSame(WebhookDeliveryStatus::Pending, $delivery->status);
        self::assertSame(1, $delivery->attempts);
        self::assertSame(503, $delivery->lastStatusCode);
        self::assertGreaterThan($now, $delivery->nextAttemptAt);
        self::assertNull($delivery->endedAt);

        foreach (range(2, 8) as $attempt) {
            $delivery = $delivery->failed(DeliveryFailure::Connection, null, 10_000, $now, $random);
        }
        self::assertSame(WebhookDeliveryStatus::Abandoned, $delivery->status);
        self::assertSame(8, $delivery->attempts);
        self::assertSame(DeliveryFailure::Connection, $delivery->lastFailure);
        self::assertEquals($now, $delivery->endedAt);

        $this->expectException(LogicException::class);
        $delivery->succeeded(200, 10, $now);
    }

    public function testASuccessEndsIt(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');

        $delivered = self::pending($now)->succeeded(204, 15, $now);

        self::assertSame(WebhookDeliveryStatus::Succeeded, $delivered->status);
        self::assertSame([1, 204, 15], [$delivered->attempts, $delivered->lastStatusCode, $delivered->lastDurationMs]);
        self::assertNull($delivered->lastFailure);
    }

    private static function pending(DateTimeImmutable $now): WebhookDelivery
    {
        return WebhookDelivery::reconstitute(
            WebhookDeliveryId::generate(new SeededRandomSource(1)),
            WebhookEndpointId::generate(new SeededRandomSource(2)),
            AuditEventId::generate(new SeededRandomSource(3)),
            WebhookDeliveryStatus::Pending,
            0,
            $now,
            null,
            null,
            null,
            $now,
            null,
        );
    }
}
