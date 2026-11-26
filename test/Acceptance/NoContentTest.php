<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Port\WebhookSender;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeWebhookSender;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An answer with no content says no `Content-Type` (RFC 9110 §8.3, #168): a `204`, the `202` of a webhook
 * test, an empty `200` from revocation. The application sets none, and the entry point stops PHP adding
 * its default (`EntryPointTest`).
 */
final class NoContentTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    public function testADeletionSaysNoContentType(): void
    {
        $this->adminToken();
        $role = $this->api(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/roles',
            ['name' => 'Auditors', 'description' => 'Reads the trail.'],
        );

        $deleted = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            '/api/v1/roles/' . (string) self::document($role)['id'],
        );

        self::assertEmptyAndUntyped(StatusCodeInterface::STATUS_NO_CONTENT, $deleted);
    }

    public function testAQueuedWebhookTestSaysNoContentType(): void
    {
        $this->container()->setService(WebhookSender::class, new FakeWebhookSender());
        $this->adminToken();
        $created = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/webhooks', [
            'url' => 'https://siem.acme.example/hooks',
            'events' => ['user.updated'],
        ]);

        $queued = $this->api(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/webhooks/' . (string) self::document($created)['id'] . '/test',
        );

        self::assertEmptyAndUntyped(StatusCodeInterface::STATUS_ACCEPTED, $queued);
    }

    public function testARevocationSaysNoContentType(): void
    {
        $this->m2mClient();

        $revoked = $this->post(
            '/oauth2/revoke',
            ['token' => 'not-a-token-this-server-issued'],
            [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );

        self::assertEmptyAndUntyped(StatusCodeInterface::STATUS_OK, $revoked);
    }

    private static function assertEmptyAndUntyped(int $status, ResponseInterface $response): void
    {
        self::assertSame($status, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('', (string) $response->getBody());
        self::assertFalse($response->hasHeader('Content-Type'), $response->getHeaderLine('Content-Type'));
    }
}
