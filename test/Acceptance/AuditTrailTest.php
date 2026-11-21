<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;

/**
 * The audit trail, end to end: what the server writes down as it works, and how an
 * operator reads it back through `GET /api/v1/audit-events`.
 *
 * Three promises are checked here. An event names who acted — the person, the machine,
 * or nobody yet — and where the request came from. A refused change leaves no event, and
 * a refused sign-in leaves one. And no credential ever reaches the trail, however the
 * event came about.
 */
final class AuditTrailTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EVENTS = '/api/v1/audit-events';
    private const string USERS = '/api/v1/users';

    public function testReadingTheTrailTakesItsOwnScope(): void
    {
        $this->adminToken(['read:users']);

        $response = $this->api('GET', self::EVENTS);

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('scope="read:audit_events"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAManagementChangeNamesTheMachineThatMadeItAndWhereFrom(): void
    {
        $this->adminToken();

        $created = $this->api(
            'POST',
            self::USERS,
            ['email' => 'new@clavia.dev', 'password' => 'a-good-password'],
            headers: ['User-Agent' => 'clavia-test/1.0'],
        );
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        /** @var mixed $userId */
        $userId = self::document($created)['id'];
        self::assertIsString($userId);

        $event = $this->onlyEvent('user.created');
        self::assertSame('success', $event['outcome']);
        self::assertSame(
            ['kind' => 'application', 'user_id' => null, 'client_id' => self::TEST_M2M_CLIENT_ID],
            $event['actor'],
        );
        self::assertSame(['type' => 'user', 'id' => $userId], $event['target']);
        self::assertSame('203.0.113.7', $event['client_address']);
        self::assertSame('clavia-test/1.0', $event['user_agent']);
    }

    public function testARefusedChangeLeavesNoEvent(): void
    {
        $this->adminToken();
        $new = ['email' => 'twice@clavia.dev', 'password' => 'a-good-password'];
        self::assertSame(201, $this->api('POST', self::USERS, $new)->getStatusCode());

        self::assertSame(409, $this->api('POST', self::USERS, $new)->getStatusCode());

        $this->onlyEvent('user.created');
    }

    public function testASignInIsRecordedForThePersonAndAFailedOneForNobody(): void
    {
        $user = $this->user();

        $this->submitLogin(password: 'not-the-password');
        $this->submitLogin();

        $this->adminToken();
        $failed = $this->onlyEvent('authentication.failed');
        self::assertSame('failure', $failed['outcome']);
        self::assertSame('anonymous', self::field($failed, 'actor', 'kind'));
        self::assertSame('wrong_password', self::field($failed, 'details', 'reason'));
        self::assertSame(self::TEST_USER_EMAIL, self::field($failed, 'details', 'email'));
        // The account is named as the target — the attempt was against it — but the
        // password typed is nowhere.
        self::assertSame(['type' => 'user', 'id' => $user->id->value], $failed['target']);
        self::assertStringNotContainsString('not-the-password', json_encode($failed, JSON_THROW_ON_ERROR));

        $succeeded = $this->onlyEvent('authentication.succeeded');
        self::assertSame('person', self::field($succeeded, 'actor', 'kind'));
        self::assertSame($user->id->value, self::field($succeeded, 'actor', 'user_id'));
        self::assertSame(['pwd'], self::field($succeeded, 'details', 'amr'));
    }

    public function testAnIssuedTokenIsRecordedWithoutTheToken(): void
    {
        $token = $this->adminToken();

        $issued = $this->onlyEvent('token.issued');

        self::assertSame('client_credentials', self::field($issued, 'details', 'grant_type'));
        self::assertSame(self::MANAGEMENT_API, self::field($issued, 'details', 'audience'));
        self::assertSame(['type' => 'client', 'id' => self::TEST_M2M_CLIENT_ID], $issued['target']);
        self::assertStringNotContainsString($token, json_encode($issued, JSON_THROW_ON_ERROR));
    }

    public function testTheTrailIsFilteredNewestFirst(): void
    {
        $this->user();
        $this->submitLogin(password: 'wrong-once');
        $this->submitLogin(password: 'wrong-twice');
        $this->submitLogin();
        $this->adminToken();

        $failures = self::document($this->api('GET', self::EVENTS, query: ['outcome' => 'failure']));
        self::assertSame(2, $failures['total']);

        $both = self::document($this->api('GET', self::EVENTS, query: [
            'type' => 'authentication.succeeded,authentication.failed',
        ]));
        self::assertSame(3, $both['total']);
        self::assertIsArray($both['items']);
        $first = $both['items'][0];
        self::assertIsArray($first);
        self::assertSame('authentication.succeeded', $first['type']);

        $byTheMachine = self::document($this->api('GET', self::EVENTS, query: [
            'client_id' => self::TEST_M2M_CLIENT_ID,
            'type' => 'token.issued',
        ]));
        self::assertSame(1, $byTheMachine['total']);
    }

    public function testAnUnknownEventTypeIsRefused(): void
    {
        $this->adminToken();

        self::assertSame(422, $this->api('GET', self::EVENTS, query: ['type' => 'user.exploded'])->getStatusCode());
    }

    /**
     * The one event of `$type` in the trail, read through the API.
     *
     * @return array<array-key, mixed>
     */
    private function onlyEvent(string $type): array
    {
        $page = self::document($this->api('GET', self::EVENTS, query: ['type' => $type]));
        self::assertSame(1, $page['total'], json_encode($page, JSON_THROW_ON_ERROR));
        self::assertIsArray($page['items']);
        $event = $page['items'][0];
        self::assertIsArray($event);

        return $event;
    }

    /** @param array<array-key, mixed> $event */
    private static function field(array $event, string $section, string $name): mixed
    {
        $values = $event[$section];
        self::assertIsArray($values);

        return $values[$name] ?? null;
    }
}
