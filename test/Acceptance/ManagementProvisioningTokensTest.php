<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;

/**
 * Provisioning tokens in the Management API (docs/design/scim-provisioning.md §5.1, slice 1):
 * issued for one connection with their value and the SCIM base URL once, stored as their digest,
 * listed with their state and how soon they expire, revoked at once.
 */
final class ManagementProvisioningTokensTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string TOKENS = '/api/v1/provisioning-tokens';

    public function testATokenIsIssuedWithItsValueAndTheBaseUrlOnce(): void
    {
        $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();

        $issued = $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, [
            'connection' => 'password',
            'description' => 'Entra ID',
            'subject_attribute' => 'userName',
            'addresses_trusted' => true,
        ]);

        self::assertSame(StatusCodeInterface::STATUS_CREATED, $issued->getStatusCode(), (string) $issued->getBody());
        $document = self::document($issued);
        self::assertIsString($document['token']);
        self::assertSame(43, strlen($document['token']));
        self::assertSame('https://management.clavia.test/scim/v2', $document['base_url']);
        self::assertSame('password', $document['connection']);
        self::assertSame('active', $document['state']);
        self::assertFalse($document['expiring_soon']);
        self::assertSame('userName', $document['subject_attribute']);
        self::assertTrue($document['addresses_trusted']);
        self::assertFalse($document['delete_deactivates']);
        self::assertIsString($document['expires_at']);
        self::assertSame('2027-01-15', substr($document['expires_at'], 0, 10), 'A year by default.');
        self::assertIsString($document['id']);
        self::assertSame(self::TOKENS . '/' . $document['id'], $issued->getHeaderLine('Location'));
        $stored = TestStorage::database()->fetchAll('SELECT * FROM provisioning_tokens');
        self::assertCount(1, $stored);
        self::assertSame(Digest::of($document['token'])->toString(), $stored[0]['token_hash']);
        self::assertStringNotContainsString($document['token'], (string) json_encode($stored));
        $event = TestStorage::database()->fetchOne(
            'SELECT details::text AS details FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::ProvisioningTokenIssued->value],
        );
        self::assertIsArray($event);
        self::assertIsString($event['details']);
        self::assertStringContainsString('"connection": "password"', $event['details']);
        self::assertStringNotContainsString($document['token'], $event['details']);
    }

    public function testOnlyAPoolOrAnEnterpriseConnectionIsProvisioned(): void
    {
        $this->adminToken();

        foreach (['google', 'email', 'nowhere'] as $connection) {
            $refused = $this->api(
                RequestMethodInterface::METHOD_POST,
                self::TOKENS,
                ['connection' => $connection, 'description' => 'Entra ID'],
            );

            self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refused->getStatusCode(), $connection);
            self::assertStringNotContainsString($connection, (string) $refused->getBody(), 'Never the value sent.');
        }
        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM provisioning_tokens'));
    }

    public function testTheListIsByConnectionAndFlagsATokenAboutToExpire(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();
        $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, [
            'connection' => 'password',
            'description' => 'Okta',
            'expires_in' => 2_678_400,
        ]);
        $clock->advance(86_400 * 2);
        $this->adminToken();

        $listed = self::document(
            $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS, query: ['connection' => 'password']),
        );
        $elsewhere = self::document(
            $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS, query: ['connection' => 'acme']),
        );

        self::assertSame(1, $listed['total']);
        self::assertIsArray($listed['items']);
        self::assertIsArray($listed['items'][0]);
        self::assertTrue($listed['items'][0]['expiring_soon'], 'Twenty-nine days left.');
        self::assertArrayNotHasKey('token', $listed['items'][0]);
        self::assertSame(0, $elsewhere['total']);
    }

    public function testATokenIsReadAndRevoked(): void
    {
        $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();
        $issued = $this->api(
            RequestMethodInterface::METHOD_POST,
            self::TOKENS,
            ['connection' => 'password', 'description' => 'Okta'],
        );
        $id = self::document($issued)['id'];
        self::assertIsString($id);

        $read = $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS . '/' . $id);
        $revoked = $this->api(RequestMethodInterface::METHOD_DELETE, self::TOKENS . '/' . $id);
        $again = $this->api(RequestMethodInterface::METHOD_DELETE, self::TOKENS . '/' . $id);

        self::assertSame(StatusCodeInterface::STATUS_OK, $read->getStatusCode());
        self::assertArrayNotHasKey('token', self::document($read));
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $revoked->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $again->getStatusCode(), 'Changes nothing.');
        self::assertSame(
            'revoked',
            self::document($this->api(RequestMethodInterface::METHOD_GET, self::TOKENS . '/' . $id))['state'],
        );
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::ProvisioningTokenRevoked->value],
        ));
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api(
                RequestMethodInterface::METHOD_GET,
                self::TOKENS . '/3e9a7c51-8b2d-4f6e-a0c4-d5b7e9f1a3c6',
            )->getStatusCode(),
        );
    }

    public function testEachOperationNeedsItsScope(): void
    {
        $this->adminToken(['read:provisioning_tokens']);

        $refused = $this->api(
            RequestMethodInterface::METHOD_POST,
            self::TOKENS,
            ['connection' => 'password', 'description' => 'Okta'],
        );

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $refused->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS)->getStatusCode(),
        );
    }

    public function testDeletingTheConnectionDeletesItsTokens(): void
    {
        $this->adminToken();
        $created = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
            'name' => 'staff',
            'display_name' => 'Staff',
            'strategy' => 'database',
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        $issued = $this->api(
            RequestMethodInterface::METHOD_POST,
            self::TOKENS,
            ['connection' => 'staff', 'description' => 'Okta'],
        );
        $id = self::document($issued)['id'];
        self::assertIsString($id);

        $deleted = $this->api(RequestMethodInterface::METHOD_DELETE, '/api/v1/connections/staff');

        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $deleted->getStatusCode(),
            (string) $deleted->getBody(),
        );
        $gone = $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS . '/' . $id);
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $gone->getStatusCode());
    }
}
