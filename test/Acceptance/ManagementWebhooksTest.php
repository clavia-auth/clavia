<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Webhooks\WebhookSecrets;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;

/**
 * Webhook endpoints through the Management API (#118, docs/design/webhooks.md §5.1): registered
 * with a secret shown once and kept sealed, rotated with a day's overlap, changed and deleted,
 * every change in the configuration trail, never a secret anywhere but the one answer.
 */
final class ManagementWebhooksTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string URL = 'https://siem.acme.example/hooks/clavia?token=receiver-own';

    public function testAnEndpointIsRegisteredWithItsSecretShownOnceAndKeptSealed(): void
    {
        $this->adminToken();

        $created = $this->api('POST', '/api/v1/webhooks', [
            'url' => self::URL,
            'description' => 'SIEM',
            'events' => ['user.updated', 'user.created'],
        ]);

        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        $document = self::document($created);
        $secret = (string) $document['secret'];
        self::assertMatchesRegularExpression('/^whsec_[A-Za-z0-9+\/]{43}=$/D', $secret);
        self::assertSame(['user.created', 'user.updated'], $document['events']);
        self::assertTrue($document['is_enabled']);
        $id = (string) $document['id'];
        self::assertSame('/api/v1/webhooks/' . $id, $created->getHeaderLine('Location'));

        // Never again: not in the list, not in the endpoint, not in the trail.
        self::assertStringNotContainsString($secret, (string) $this->api('GET', '/api/v1/webhooks')->getBody());
        self::assertArrayNotHasKey('secret', self::document($this->api('GET', '/api/v1/webhooks/' . $id)));
        $trail = (string) TestStorage::database()->fetchValue(
            "SELECT details::text FROM audit_events WHERE type = 'webhook.created'",
        );
        self::assertStringContainsString('siem.acme.example', $trail);
        self::assertStringNotContainsString('receiver-own', $trail, 'The host, never the path or query.');
        self::assertStringNotContainsString($secret, $trail);

        // Sealed with the endpoint's id as associated data, never in the clear, never hashed.
        $sealed = (string) TestStorage::database()->fetchValue('SELECT secret_sealed FROM webhook_endpoints');
        self::assertStringNotContainsString($secret, $sealed);
        self::assertSame($secret, $this->container()->get(SecretCipher::class)->decrypt(
            $sealed,
            WebhookSecrets::context(WebhookEndpointId::fromString($id)),
        ));
    }

    public function testStreamingTheTrailNeedsTheRightToReadIt(): void
    {
        $this->adminToken(['create:webhooks', 'read:webhooks', 'update:webhooks']);

        $refused = $this->api('POST', '/api/v1/webhooks', ['url' => self::URL, 'events' => ['*']]);

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $refused->getStatusCode());
        self::assertStringContainsString('read:audit_events', $refused->getHeaderLine('WWW-Authenticate'));
        self::assertSame(0, $this->container()->get(WebhookEndpointRepository::class)->count());

        $endpoint = $this->anEndpoint(1);
        $path = '/api/v1/webhooks/' . $endpoint->id->value;
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api('PATCH', $path, ['events' => ['*']])->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api('PATCH', $path, ['url' => 'https://other.example/'])->getStatusCode(),
        );
        $described = $this->api('PATCH', $path, ['description' => 'Paused', 'is_enabled' => false]);
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $described->getStatusCode(),
            'The rest needs update:webhooks alone.',
        );
        self::assertFalse(self::document($described)['is_enabled']);
    }

    public function testWhatCannotBeSentToOrHeardIsRefused(): void
    {
        $this->adminToken();

        foreach (['http://siem.acme.example/hooks', 'https://127.0.0.1/hooks', 'https://10.0.0.1/hooks'] as $url) {
            $response = $this->api('POST', '/api/v1/webhooks', ['url' => $url, 'events' => ['*']]);
            self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $response->getStatusCode(), $url);
            self::assertStringNotContainsString('127.0.0.1', (string) $response->getBody(), 'Never the address.');
        }
        $unknown = $this->api('POST', '/api/v1/webhooks', ['url' => self::URL, 'events' => ['user.exploded']]);
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $unknown->getStatusCode());

        foreach (range(1, WebhookEndpoint::MAX_ENDPOINTS) as $i) {
            $this->anEndpoint($i);
        }
        $twentyFirst = $this->api('POST', '/api/v1/webhooks', ['url' => self::URL, 'events' => ['*']]);
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $twentyFirst->getStatusCode());
        self::assertCount(20, self::json($this->api('GET', '/api/v1/webhooks')));
    }

    public function testRotatingKeepsThePreviousSecretSigningForADay(): void
    {
        $this->freezeClock('2026-03-04T09:00:00Z');
        $this->adminToken();
        $first = self::document($this->api('POST', '/api/v1/webhooks', ['url' => self::URL, 'events' => ['*']]));
        $path = '/api/v1/webhooks/' . (string) $first['id'];

        $rotated = $this->api('POST', $path . '/rotate-secret');

        self::assertSame(StatusCodeInterface::STATUS_OK, $rotated->getStatusCode(), (string) $rotated->getBody());
        $document = self::document($rotated);
        self::assertNotSame($first['secret'], $document['secret']);
        self::assertSame('2026-03-05T09:00:00Z', $document['previous_secret_until']);
        $stored = $this->container()->get(WebhookEndpointRepository::class)->find(
            WebhookEndpointId::fromString((string) $first['id']),
        );
        self::assertNotNull($stored);
        self::assertNotNull($stored->previousSecretAt(new DateTimeImmutable('2026-03-05T08:59:59Z')));
        self::assertSame(
            1,
            (int) TestStorage::database()->fetchValue(
                "SELECT count(*) FROM audit_events WHERE type = 'webhook.secret_rotated'",
            ),
        );
    }

    public function testAnEndpointIsChangedThenDeleted(): void
    {
        $this->adminToken();
        $endpoint = $this->anEndpoint(1);
        $path = '/api/v1/webhooks/' . $endpoint->id->value;

        $changed = $this->api('PATCH', $path, ['events' => ['*'], 'url' => 'https://alerts.acme.example/clavia']);
        self::assertSame(['*'], self::document($changed)['events']);
        self::assertSame('https://alerts.acme.example/clavia', self::document($changed)['url']);
        $fields = (string) TestStorage::database()->fetchValue(
            "SELECT details::text FROM audit_events WHERE type = 'webhook.updated'",
        );
        self::assertStringContainsString('events', $fields);
        self::assertStringNotContainsString('alerts.acme.example', $fields, 'The fields, never their values.');

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->api('DELETE', $path)->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->api('GET', $path)->getStatusCode());
        self::assertSame(
            1,
            (int) TestStorage::database()->fetchValue(
                "SELECT count(*) FROM audit_events WHERE type = 'webhook.deleted'",
            ),
        );
    }

    private function anEndpoint(int $seed): WebhookEndpoint
    {
        $endpoint = WebhookEndpoint::register(
            WebhookEndpointId::generate(new SeededRandomSource($seed)),
            Url::fromString('https://hooks' . $seed . '.example/audit'),
            '',
            EventFilter::all(),
            'sealed',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->container()->get(WebhookEndpointRepository::class)->save($endpoint);

        return $endpoint;
    }
}
