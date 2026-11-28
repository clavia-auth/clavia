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
 * Initial access tokens in the Management API (RFC 7591 §3; docs/design/
 * dynamic-client-registration.md, slice 1): issued with their value once, stored as its digest,
 * listed with their state, revoked at once.
 */
final class ManagementInitialAccessTokensTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string TOKENS = '/api/v1/initial-access-tokens';

    public function testATokenIsIssuedWithItsValueOnceAndStoredAsItsDigest(): void
    {
        $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();

        $issued = $this->api(
            RequestMethodInterface::METHOD_POST,
            self::TOKENS,
            ['description' => 'Acme partner portal', 'max_uses' => 5],
        );

        self::assertSame(StatusCodeInterface::STATUS_CREATED, $issued->getStatusCode(), (string) $issued->getBody());
        $document = self::document($issued);
        self::assertIsString($document['token']);
        self::assertSame(43, strlen($document['token']));
        self::assertSame('Acme partner portal', $document['description']);
        self::assertSame(5, $document['max_uses']);
        self::assertSame(0, $document['uses']);
        self::assertSame('active', $document['state']);
        self::assertSame('2026-01-22T10:00:00Z', self::utc($document['expires_at']), 'Seven days by default.');
        self::assertIsString($document['id']);
        self::assertSame(self::TOKENS . '/' . $document['id'], $issued->getHeaderLine('Location'));
        $stored = TestStorage::database()->fetchAll('SELECT * FROM initial_access_tokens');
        self::assertCount(1, $stored);
        self::assertSame(Digest::of($document['token'])->toString(), $stored[0]['token_hash']);
        self::assertStringNotContainsString($document['token'], (string) json_encode($stored));
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::InitialAccessTokenIssued->value],
        ));
    }

    public function testTheListNamesEachTokenAndItsStateButNeverItsValue(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();
        $short = self::document(
            $this->api(
                RequestMethodInterface::METHOD_POST,
                self::TOKENS,
                ['description' => 'Short', 'expires_in' => 60],
            ),
        );
        $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, ['description' => 'Long']);
        $clock->advance(120);

        $listed = self::document($this->api(RequestMethodInterface::METHOD_GET, self::TOKENS));

        self::assertSame(2, $listed['total']);
        self::assertIsArray($listed['items']);
        $states = [];
        foreach ($listed['items'] as $item) {
            self::assertIsArray($item);
            self::assertArrayNotHasKey('token', $item);
            self::assertIsString($item['description']);
            self::assertIsString($item['state']);
            $states[$item['description']] = $item['state'];
        }
        ksort($states);
        self::assertSame(['Long' => 'active', 'Short' => 'expired'], $states);
        self::assertIsString($short['token']);
        self::assertStringNotContainsString(
            $short['token'],
            (string) $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS)->getBody(),
        );
    }

    public function testARevokedTokenSaysSoAndRevokingItAgainChangesNothing(): void
    {
        $this->adminToken();
        $id = self::document(
            $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, ['description' => 'Partner']),
        )['id'];
        self::assertIsString($id);

        $revoked = $this->api(RequestMethodInterface::METHOD_DELETE, self::TOKENS . '/' . $id);
        $again = $this->api(RequestMethodInterface::METHOD_DELETE, self::TOKENS . '/' . $id);

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $revoked->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $again->getStatusCode());
        $items = self::document($this->api(RequestMethodInterface::METHOD_GET, self::TOKENS))['items'];
        self::assertIsArray($items);
        self::assertIsArray($items[0]);
        self::assertSame('revoked', $items[0]['state']);
        self::assertIsString($items[0]['revoked_at']);
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::InitialAccessTokenRevoked->value],
        ), 'Revoked once.');
    }

    public function testAnUnknownTokenIsNotFound(): void
    {
        $this->adminToken();

        $response = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            self::TOKENS . '/0b0f5a3e-8f2c-4d1a-9b7e-3c2d1e0f9a8b',
        );

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $response->getStatusCode());
    }

    /**
     * @param array<string, mixed> $body
     * @param int $status 400 for what the contract refuses, 422 for what a rule does.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('outOfBounds')]
    public function testWhatIsOutOfBoundsIsRefused(array $body, int $status): void
    {
        $this->adminToken();

        $response = $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, $body);

        self::assertSame($status, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM initial_access_tokens'));
    }

    /** @return iterable<string, array{array<string, mixed>, int}> */
    public static function outOfBounds(): iterable
    {
        $built = StatusCodeInterface::STATUS_BAD_REQUEST;
        yield 'no description' => [['max_uses' => 1], $built];
        yield 'an empty description' => [['description' => ''], $built];
        yield 'a description too long' => [['description' => str_repeat('a', 121)], $built];
        // One line is the domain's rule, not the contract's.
        $ruled = StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY;
        yield 'a control character' => [['description' => "two\nlines"], $ruled];
        yield 'no use' => [['description' => 'x', 'max_uses' => 0], $built];
        yield 'too many uses' => [['description' => 'x', 'max_uses' => 1001], $built];
        yield 'too short a life' => [['description' => 'x', 'expires_in' => 59], $built];
        yield 'too long a life' => [['description' => 'x', 'expires_in' => 7_776_001], $built];
    }

    public function testEachOperationNeedsItsScope(): void
    {
        $this->adminToken(['read:initial_access_tokens']);

        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->api(RequestMethodInterface::METHOD_GET, self::TOKENS)->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api(RequestMethodInterface::METHOD_POST, self::TOKENS, ['description' => 'x'])->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api(
                RequestMethodInterface::METHOD_DELETE,
                self::TOKENS . '/0b0f5a3e-8f2c-4d1a-9b7e-3c2d1e0f9a8b',
            )->getStatusCode(),
        );
    }

    private static function utc(mixed $instant): string
    {
        self::assertIsString($instant);

        return new \DateTimeImmutable($instant)->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
}
