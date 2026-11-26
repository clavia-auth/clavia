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
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Port\SendOutcome;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\WebhookSender;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Webhook\DeliveryFailure;
use Clavia\Domain\Webhook\StandardWebhookSignature;
use Clavia\Domain\Webhook\WebhookSecret;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeWebhookSender;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
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

        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/users/' . $user->id->value, ['name' => 'Ada King']);
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
        $listed = self::document(
            $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/audit-events', query: ['type' => 'user.updated']),
        );
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
        $this->api(
            RequestMethodInterface::METHOD_PATCH,
            '/api/v1/users/' . $this->user()->id->value,
            ['name' => 'Ada King'],
        );
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
        $this->api(
            RequestMethodInterface::METHOD_PATCH,
            '/api/v1/users/' . $this->user()->id->value,
            ['name' => 'Ada King'],
        );
        $id = (string) TestStorage::database()->fetchValue('SELECT id FROM webhook_endpoints');
        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/webhooks/' . $id, ['is_enabled' => false]);

        self::assertStringContainsString('1 abandoned', $this->deliver());
        self::assertSame([], $this->wire->sent);
        self::assertSame(
            'disabled',
            TestStorage::database()->fetchValue('SELECT last_failure FROM webhook_deliveries'),
        );
    }

    public function testATestEventGoesToTheEndpointTestedAloneAndShowsInItsLog(): void
    {
        $clock = $this->freezeClock('2026-03-04T09:30:00Z');
        $this->adminToken();
        $secret = $this->registerWebhook(['*']);
        $tested = (string) TestStorage::database()->fetchValue('SELECT id FROM webhook_endpoints');
        $this->registerWebhook(['*'], 'https://alerts.acme.example/clavia');

        $clock->advance(60);
        $queued = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/webhooks/' . $tested . '/test');
        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $queued->getStatusCode(), (string) $queued->getBody());
        $this->deliver();

        // The other endpoint hears that a test was asked for (webhook.tested is not among its
        // events, even past "*"), and the creations; only the endpoint tested gets the test.
        $tests = array_values(array_filter(
            $this->wire->sent,
            static fn (array $sent): bool => str_contains($sent['body'], '"type":"webhook.tested"'),
        ));
        self::assertCount(1, $tests);
        self::assertSame('https://siem.acme.example/hooks', $tests[0]['url']);
        self::assertSame(
            StandardWebhookSignature::header(
                $tests[0]['headers']['webhook-id'],
                (int) $tests[0]['headers']['webhook-timestamp'],
                $tests[0]['body'],
                [WebhookSecret::unsealed($secret)],
            ),
            $tests[0]['headers']['webhook-signature'],
        );

        $log = $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/webhooks/' . $tested . '/deliveries');
        self::assertSame(StatusCodeInterface::STATUS_OK, $log->getStatusCode(), (string) $log->getBody());
        /** @var array{items: list<array<string, mixed>>, total: int} $page */
        $page = self::document($log);
        self::assertSame('webhook.tested', $page['items'][0]['event_type']);
        self::assertSame('succeeded', $page['items'][0]['status']);
        self::assertSame(200, $page['items'][0]['last_status_code']);
        self::assertSame($tests[0]['headers']['webhook-id'], $page['items'][0]['event_id']);
        self::assertStringNotContainsString('"body"', (string) $log->getBody());
    }

    public function testTestingNeedsTheRightToReadTheTrailAndAnEndpointSwitchedOn(): void
    {
        $this->adminToken();
        $this->registerWebhook(['*']);
        $id = (string) TestStorage::database()->fetchValue('SELECT id FROM webhook_endpoints');
        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/webhooks/' . $id, ['is_enabled' => false]);

        self::assertSame(
            StatusCodeInterface::STATUS_CONFLICT,
            $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/webhooks/' . $id . '/test')->getStatusCode(),
        );
        $this->adminToken(['update:webhooks', 'read:webhooks']);
        $refused = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/webhooks/' . $id . '/test');
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $refused->getStatusCode());
        self::assertStringContainsString('read:audit_events', $refused->getHeaderLine('WWW-Authenticate'));
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/webhooks/' . $id . '/deliveries')->getStatusCode(),
            'The log names audit events: a view of the trail.',
        );
        $this->adminToken();
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api(
                RequestMethodInterface::METHOD_GET,
                '/api/v1/webhooks/6b0e5c9a-2f4d-4a1e-9b3c-7d8e9f0a1b2c/deliveries',
            )->getStatusCode(),
        );
    }

    public function testAnEndpointFailingForFiveDaysIsSwitchedOffUntilSwitchedOnAgain(): void
    {
        $clock = $this->freezeClock('2026-03-04T09:00:00Z');
        $this->adminToken();
        $this->registerWebhook(['user.updated']);
        $id = (string) TestStorage::database()->fetchValue('SELECT id FROM webhook_endpoints');
        $user = $this->user();
        $this->wire->answers = array_fill(0, 40, SendOutcome::unsent(DeliveryFailure::Connection, 10_000));

        // A new event a day, every one of them failing.
        foreach (range(1, 5) as $day) {
            $this->api(
                RequestMethodInterface::METHOD_PATCH,
                '/api/v1/users/' . $user->id->value,
                ['name' => 'Ada ' . $day],
            );
            $this->deliver();
            self::assertSame('2026-03-04T09:00:00Z', self::webhook($this, $id)['failing_since']);
            self::assertTrue(self::webhook($this, $id)['is_enabled'], 'Day ' . $day);
            $clock->advance(86_400);
            $this->adminToken();
        }
        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/users/' . $user->id->value, ['name' => 'Ada 6']);

        self::assertStringContainsString('Switched off 1 endpoint(s) failing for 5 days.', $this->deliver());
        $off = self::webhook($this, $id);
        self::assertFalse($off['is_enabled']);
        self::assertSame('failing', $off['disabled_reason']);
        /** @var array{items: list<array{actor: array{kind: string}, details: array<string, mixed>}>} $trail */
        $trail = self::document(
            $this->api(
                RequestMethodInterface::METHOD_GET,
                '/api/v1/audit-events',
                query: ['type' => 'webhook.disabled'],
            ),
        );
        self::assertSame('system', $trail['items'][0]['actor']['kind']);
        self::assertSame(['days' => 5, 'reason' => 'failing'], $trail['items'][0]['details']);
        self::assertStringContainsString('abandoned', $this->deliver(), 'Its pending deliveries end.');

        $on = $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/webhooks/' . $id, ['is_enabled' => true]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $on->getStatusCode());
        self::assertSame([true, null, null], [
            self::document($on)['is_enabled'],
            self::document($on)['disabled_reason'],
            self::document($on)['failing_since'],
        ]);
    }

    /** @return array<string, mixed> */
    private static function webhook(self $test, string $id): array
    {
        /** @var array<string, mixed> */
        return self::document($test->api(RequestMethodInterface::METHOD_GET, '/api/v1/webhooks/' . $id));
    }

    /**
     * @param list<string> $events
     *
     * @return non-empty-string The secret.
     */
    private function registerWebhook(array $events, string $url = 'https://siem.acme.example/hooks'): string
    {
        $created = $this->api(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/webhooks',
            ['url' => $url, 'events' => $events],
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
        // The shell, as cron runs it: nobody is acting, so the system is the actor.
        $this->container()->get(AuditContext::class)->begin(null, null);
        $tester = new CommandTester($this->container()->get(DeliverWebhooksCommand::class));
        $tester->execute([]);

        return $tester->getDisplay(true);
    }
}
