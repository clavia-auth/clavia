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
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;

/**
 * Signing keys in the Management API: what `clavia keys:list` and `keys:rotate` do, for the
 * `postgres` backend — and never any key material in an answer.
 */
final class ManagementSigningKeysTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    public function testTheKeysAreListedWithoutTheirMaterial(): void
    {
        $this->adminToken();

        $response = $this->api('GET', '/api/v1/signing-keys');

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        $keys = self::document($response);
        self::assertCount(1, $keys);
        self::assertIsArray($keys[0]);
        self::assertSame('active', $keys[0]['status']);
        self::assertSame('RS256', $keys[0]['algorithm']);
        self::assertTrue($keys[0]['published']);
        self::assertNull($keys[0]['published_until']);
        self::assertSame($this->publishedKids(), [$keys[0]['kid']]);
        self::assertNoKeyMaterialIn((string) $response->getBody());
    }

    public function testARotationRetiresTheActiveKeyAndKeepsItPublished(): void
    {
        $this->adminToken();
        $before = self::document($this->api('GET', '/api/v1/signing-keys'));
        self::assertIsArray($before[0]);

        $rotated = $this->api('POST', '/api/v1/signing-keys/rotate');

        self::assertSame(StatusCodeInterface::STATUS_OK, $rotated->getStatusCode(), (string) $rotated->getBody());
        $rotation = self::document($rotated);
        self::assertIsArray($rotation['active']);
        self::assertIsArray($rotation['retired']);
        self::assertSame($before[0]['kid'], $rotation['retired']['kid']);
        self::assertSame('retired', $rotation['retired']['status']);
        self::assertIsString($rotation['retired']['published_until']);
        self::assertNotSame($before[0]['kid'], $rotation['active']['kid']);
        // Both are published: relying parties find the new key, and the old one's tokens verify.
        self::assertEqualsCanonicalizing(
            [$rotation['active']['kid'], $rotation['retired']['kid']],
            $this->publishedKids(),
        );
        self::assertNoKeyMaterialIn((string) $rotated->getBody());
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::SigningKeyRotated->value],
        ));
    }

    public function testEachOperationNeedsItsScope(): void
    {
        $this->adminToken(['read:signing_keys']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->api('GET', '/api/v1/signing-keys')->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api('POST', '/api/v1/signing-keys/rotate')->getStatusCode(),
        );
    }

    public function testARemoteBackendKeepsItsKeysAtTheProvider(): void
    {
        $this->boot([
            'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
            'CLAVIA_SIGNING_KEY_REF' => 'arn:aws:kms:eu-west-1:123456789012:key/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0',
        ]);
        $this->adminToken();

        self::assertSame(
            StatusCodeInterface::STATUS_CONFLICT,
            $this->api('GET', '/api/v1/signing-keys')->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_CONFLICT,
            $this->api('POST', '/api/v1/signing-keys/rotate')->getStatusCode(),
        );
    }

    /** @return list<string> */
    private function publishedKids(): array
    {
        $keys = self::json($this->get('/oidc/jwks.json'))['keys'];
        self::assertIsArray($keys);

        return array_map(static function (mixed $key): string {
            self::assertIsArray($key);
            self::assertIsString($key['kid']);

            return $key['kid'];
        }, array_values($keys));
    }

    private static function assertNoKeyMaterialIn(string $body): void
    {
        // Neither the private parts of an RSA key nor its public modulus: an answer names keys.
        foreach (['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', '"n"', '"e"', 'PRIVATE KEY', 'sealed'] as $part) {
            self::assertStringNotContainsString($part, $body);
        }
    }
}
