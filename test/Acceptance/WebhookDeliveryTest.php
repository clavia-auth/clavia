<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\DeliverWebhooksCommand;
use Clavia\Application\Audit\Audit;
use Clavia\Application\Port\SendOutcome;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\WebhookSender;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Webhook\StandardWebhookSignature;
use Clavia\Domain\Webhook\WebhookSecret;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeWebhookSender;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use RuntimeException;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Webhook delivery end to end (#119, docs/design/webhooks.md §5.2, §5.3): an audit event queued in
 * its own transaction, sent by `webhooks:deliver` signed per Standard Webhooks as the Management
 * API renders it, retried on the schedule, abandoned when the retries run out or the endpoint is off.
 */
final class WebhookDeliveryTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private FakeWebhookSender $wire;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->wire = new FakeWebhookSender();
        $this->container()->setService(WebhookSender::class, $this->wire);
    }

    public function testAnAuditEventIsDeliveredSignedAndAsTheApiShowsIt(): void
    {
        $this->freezeClock('2026-03-04T09:00:00Z');
        $this->adminToken();
        $secret = $this->registerWebhook(['user.updated']);
        $user = $this->user();

        $this->api('PATCH', '/api/v1/users/' . $user->id->value, ['name' => 'Ada King']);
        self::assertSame(1, self::deliveryCount("WHERE status = 'pending'"));

        self::assertSame(
            "Delivered 1; 0 failed and will be retried; 0 abandoned; 0 old deliveries purged.\n",
            $this->deliver(),
        );

        $sent = $this->wire->sent[0];
        self::assertSame('https://siem.acme.example/hooks', $sent['url']);
        /** @var array{type: string, timestamp: string, data: array<string, mixed>} $body */
        $body = json_decode($sent['body'], true, 16, JSON_THROW_ON_ERROR);
        self::assertSame('user.updated', $body['type']);
        /** @var array{items: list<array<string, mixed>>} $listed */
        $listed = self::document($this->api('GET', '/api/v1/audit-events', query: ['type' => 'user.updated']));
        self::assertSame($listed['items'][0], $body['data'], 'Exactly what the audit API returns.');
        $headers = $sent['headers'];
        self::assertSame($body['data']['id'], $headers['webhook-id']);
        self::assertSame(
            StandardWebhookSignature::header(
                $headers['webhook-id'],
                (int) $headers['webhook-timestamp'],
                $sent['body'],
                [WebhookSecret::unsealed($secret)],
            ),
            $headers['webhook-signature'],
            'Verifiable with the secret the operator was given.',
        );
        self::assertSame('succeeded', TestStorage::database()->fetchValue('SELECT status FROM webhook_deliveries'));
    }

    public function testARolledBackChangeSendsNothing(): void
    {
        $this->adminToken();
        $this->registerWebhook(['*']);
        $transactions = $this->container()->get(TransactionManager::class);
        $audit = $this->container()->get(Audit::class);
        $before = self::deliveryCount();

        try {
            $transactions->transactional(static function () use ($audit): void {
                $audit->record(AuditEventType::RoleCreated);
                throw new RuntimeException('The change fails after its event.');
            });
        } catch (RuntimeException) {
        }

        self::assertSame($before, self::deliveryCount());
    }

    public function testAFailureIsRetriedOnTheScheduleThenAbandoned(): void
    {
        $clock = $this->freezeClock('2026-03-04T09:00:00Z');
        $this->adminToken();
        $this->registerWebhook(['user.updated']);
        $this->api('PATCH', '/api/v1/users/' . $this->user()->id->value, ['name' => 'Ada King']);
        $unavailable = SendOutcome::refused(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, 20);
        $this->wire->answers = array_fill(0, 8, $unavailable);

        self::assertStringStartsWith('Delivered 0; 1 failed', $this->deliver());
        self::assertStringStartsWith('Delivered 0; 0 failed', $this->deliver(), 'Not due again yet.');
        foreach ([6, 330, 1980, 7920, 19_800, 39_600] as $wait) {
            $clock->advance($wait);
            self::assertStringStartsWith('Delivered 0; 1 failed', $this->deliver());
        }
        $clock->advance(39_600);
        self::assertStringStartsWith('Delivered 0; 0 failed and will be retried; 1 abandoned', $this->deliver());

        self::assertCount(8, $this->wire->sent);
        self::assertSame(
            ['abandoned', 8, 503, 'status'],
            array_values((array) TestStorage::database()->fetchOne(
                'SELECT status, attempts, last_status_code, last_failure FROM webhook_deliveries',
            )),
        );
    }

    public function testASwitchedOffEndpointsDeliveriesAreAbandoned(): void
    {
        $this->adminToken();
        $this->registerWebhook(['user.updated']);
        $this->api('PATCH', '/api/v1/users/' . $this->user()->id->value, ['name' => 'Ada King']);
        $id = (string) TestStorage::database()->fetchValue('SELECT id FROM webhook_endpoints');
        $this->api('PATCH', '/api/v1/webhooks/' . $id, ['is_enabled' => false]);

        self::assertStringContainsString('1 abandoned', $this->deliver());
        self::assertSame([], $this->wire->sent);
        self::assertSame(
            'disabled',
            TestStorage::database()->fetchValue('SELECT last_failure FROM webhook_deliveries'),
        );
    }

    /**
     * @param list<string> $events
     *
     * @return non-empty-string The secret.
     */
    private function registerWebhook(array $events): string
    {
        $created = $this->api(
            'POST',
            '/api/v1/webhooks',
            ['url' => 'https://siem.acme.example/hooks', 'events' => $events],
        );
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        $secret = (string) self::document($created)['secret'];
        assert($secret !== '');

        return $secret;
    }

    private static function deliveryCount(string $where = ''): int
    {
        return (int) TestStorage::database()->fetchValue('SELECT count(*) FROM webhook_deliveries ' . $where);
    }

    private function deliver(): string
    {
        $tester = new CommandTester($this->container()->get(DeliverWebhooksCommand::class));
        $tester->execute([]);

        return $tester->getDisplay(true);
    }
}
