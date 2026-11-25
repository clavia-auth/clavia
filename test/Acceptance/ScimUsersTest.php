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
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use ClaviaTest\Support\TestStorage;
use DOMDocument;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Creating, reading and listing users through SCIM (RFC 7644 §3.3, §3.4;
 * docs/design/scim-provisioning.md §5.3, §5.4, slice 2): the sequences Entra ID and Okta send for
 * their first sync, the refusals, one connection per token, and an enterprise connection whose first
 * sign-in finds the account provisioned for it, or refuses anyone else when it requires provisioning.
 */
final class ScimUsersTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;
    use LoginFixtures;

    private const string USERS = '/scim/v2/Users';
    private const string SESSION_COOKIE = 'clavia_session';
    private const int BAD = StatusCodeInterface::STATUS_BAD_REQUEST;
    /** The subject the test identity provider asserts by default (its NameID). */
    private const string SUBJECT = 'a8f3c2d1-0b9e-4f7a-8c6d-5e4f3a2b1c0d';

    /** What Entra ID's provisioning service posts (its documented request, trimmed of nothing). */
    private const string ENTRA_USER = <<<'JSON'
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
            "externalId": "ada",
            "userName": "Ada@contoso.com",
            "active": true,
            "addresses": [{"primary": true, "type": "work", "postalCode": "SW1A"}],
            "displayName": "Ada Lovelace",
            "emails": [{"primary": true, "type": "work", "value": "ada@contoso.com"}],
            "meta": {"resourceType": "User"},
            "name": {"familyName": "Lovelace", "givenName": "Ada"},
            "phoneNumbers": [{"primary": true, "type": "work", "value": "123-555-0100"}],
            "title": "Analyst",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Engines"}
        }
        JSON;

    /** What Okta posts, a password among it when the app is set to push one. */
    private const string OKTA_USER = <<<'JSON'
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "grace@example.com",
            "name": {"givenName": "Grace", "familyName": "Hopper"},
            "emails": [{"primary": true, "value": "grace@example.com", "type": "work"}],
            "displayName": "Grace Hopper",
            "locale": "en-US",
            "externalId": "00u1abcd",
            "groups": [],
            "password": "1mPassword!",
            "active": true
        }
        JSON;

    public function testEntraIdsFirstSyncCreatesTheAccountItLooksFor(): void
    {
        $this->freezeClock('2026-01-15T10:00:00Z');
        [$token, $tokenId] = $this->provisioningToken('password');

        $before = $this->filtered($token, 'userName eq "ada@contoso.com"');
        $created = $this->scim('POST', self::USERS, $token, self::ENTRA_USER);
        $after = $this->filtered($token, 'userName eq "ADA@CONTOSO.COM"');

        self::assertSame(0, $before['totalResults']);
        self::assertSame([], $before['Resources']);
        self::assertCreated($created);
        self::assertSame('application/scim+json', $created->getHeaderLine('Content-Type'));
        $user = self::document($created);
        self::assertIsString($user['id']);
        $location = 'https://management.clavia.test/scim/v2/Users/' . $user['id'];
        self::assertSame($location, $created->getHeaderLine('Location'));
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:User'], $user['schemas']);
        self::assertSame('Ada@contoso.com', $user['userName'], 'As sent.');
        self::assertSame('ada', $user['externalId']);
        self::assertTrue($user['active']);
        self::assertSame('Ada Lovelace', $user['displayName']);
        self::assertSame(['givenName' => 'Ada', 'familyName' => 'Lovelace'], $user['name']);
        self::assertSame([['value' => 'ada@contoso.com', 'primary' => true]], $user['emails']);
        self::assertArrayNotHasKey('title', $user, 'Ignored.');
        self::assertIsArray($user['meta']);
        self::assertSame('User', $user['meta']['resourceType']);
        self::assertSame('2026-01-15T10:00:00Z', $user['meta']['created']);
        self::assertSame(1, $after['totalResults']);
        self::assertSame($user, self::document($this->scim('GET', self::USERS . '/' . $user['id'], $token)));
        $account = TestStorage::database()->fetchOne(
            'SELECT connection, email_verified, password_hash FROM users WHERE id = :id',
            ['id' => $user['id']],
        );
        self::assertSame(['connection' => 'password', 'email_verified' => false, 'password_hash' => null], $account);
        $event = TestStorage::database()->fetchOne(
            'SELECT actor_kind, actor_provisioning_token_id FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::UserCreated->value],
        );
        self::assertSame(['actor_kind' => 'provisioning', 'actor_provisioning_token_id' => $tokenId], $event);
    }

    public function testOktasPasswordIsRefusedAndTheRestCreatesTheAccount(): void
    {
        [$token] = $this->provisioningToken('password', ['addresses_trusted' => true]);
        $okta = json_decode(self::OKTA_USER, false, 8, JSON_THROW_ON_ERROR);
        self::assertInstanceOf(\stdClass::class, $okta);

        $withPassword = $this->scim('POST', self::USERS, $token, self::OKTA_USER);
        unset($okta->password);
        $created = $this->scim('POST', self::USERS, $token, (string) json_encode($okta));

        self::assertScimError(self::BAD, $withPassword, 'invalidValue');
        self::assertStringNotContainsString('1mPassword', (string) $withPassword->getBody());
        self::assertCreated($created);
        self::assertSame('en-US', self::document($created)['locale']);
        self::assertTrue(TestStorage::database()->fetchValue(
            'SELECT email_verified FROM users WHERE email = :email',
            ['email' => 'grace@example.com'],
        ), 'The token trusts the directory for addresses.');
    }

    public function testATakenUserNameExternalIdOrAddressIsAConflict(): void
    {
        [$token] = $this->provisioningToken('password');
        $this->scim('POST', self::USERS, $token, self::resource('ada', '1', 'ada@x.test'));
        $taken = [
            self::resource('ADA', '2', 'a2@x.test'),
            self::resource('other', '1', 'a3@x.test'),
            self::resource('third', '3', 'ada@x.test'),
        ];

        foreach ($taken as $resource) {
            $conflict = $this->scim('POST', self::USERS, $token, $resource);

            self::assertScimError(StatusCodeInterface::STATUS_CONFLICT, $conflict, 'uniqueness');
            self::assertStringNotContainsString('@x.test', (string) $conflict->getBody(), 'Never the value.');
        }
        self::assertSame(1, self::rows('SELECT count(*) FROM provisioned_accounts'));
        self::assertSame(
            0,
            self::rows("SELECT count(*) FROM users WHERE email IN ('a2@x.test', 'a3@x.test')"),
            'Nothing left behind.',
        );
    }

    public function testWhatIsRefusedBeforeAnythingIsCreated(): void
    {
        [$token] = $this->provisioningToken('password');

        $post = fn (string $body): ResponseInterface => $this->scim('POST', self::USERS, $token, $body);
        $plain = ['Authorization' => 'Bearer ' . $token, 'Content-Type' => 'text/plain'];
        $tooLarge = '{"userName": "' . str_repeat('a', 1_048_577) . '"}';

        self::assertScimError(self::BAD, $post('{"userName": '), 'invalidSyntax');
        self::assertScimError(self::BAD, $post('["a"]'), 'invalidSyntax');
        self::assertScimError(
            self::BAD,
            $this->request('POST', self::USERS, $plain, self::MANAGEMENT_HOST, '{}'),
            'invalidSyntax',
        );
        self::assertScimError(StatusCodeInterface::STATUS_PAYLOAD_TOO_LARGE, $post($tooLarge));
        self::assertScimError(self::BAD, $post('{"userName": "no-address"}'), 'invalidValue');
        $filtered = $this->scim('GET', self::USERS . '?filter=' . rawurlencode('title co "x"'), $token);
        self::assertScimError(self::BAD, $filtered, 'invalidFilter');
        self::assertScimError(self::BAD, $this->scim('GET', self::USERS . '?count=many', $token), 'invalidValue');
        self::assertSame(0, self::rows('SELECT count(*) FROM provisioned_accounts'));
    }

    public function testATokenSeesItsConnectionsAccountsOnly(): void
    {
        $this->adminToken();
        $this->api('POST', '/api/v1/connections', [
            'name' => 'staff',
            'display_name' => 'Staff',
            'strategy' => 'database',
        ]);
        [$ours] = $this->provisioningToken('password');
        [$theirs] = $this->provisioningToken('staff');
        $ada = self::document($this->scim('POST', self::USERS, $ours, '{"userName": "ada@x.test"}'));
        self::assertIsString($ada['id']);

        $notFound = StatusCodeInterface::STATUS_NOT_FOUND;
        self::assertScimError($notFound, $this->scim('GET', self::USERS . '/' . $ada['id'], $theirs));
        self::assertSame(0, self::document($this->scim('GET', self::USERS, $theirs))['totalResults']);
        self::assertScimError($notFound, $this->scim('GET', self::USERS . '/not-an-id', $ours));
        $second = $this->scim('POST', self::USERS, $theirs, '{"userName": "ada@x.test"}');
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $second->getStatusCode(),
            'Another connection, another account.',
        );
    }

    public function testAListIsPagedOldestFirst(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        [$token] = $this->provisioningToken('password');
        foreach (['a', 'b', 'c'] as $name) {
            $this->scim('POST', self::USERS, $token, sprintf('{"userName": "%s@x.test"}', $name));
            $clock->advance(1);
        }

        $page = self::document($this->scim('GET', self::USERS . '?startIndex=2&count=1', $token));
        $counted = self::document($this->scim('GET', self::USERS . '?count=0', $token));

        self::assertSame(3, $page['totalResults']);
        self::assertSame(2, $page['startIndex']);
        self::assertSame(1, $page['itemsPerPage']);
        self::assertIsArray($page['Resources']);
        self::assertIsArray($page['Resources'][0]);
        self::assertSame('b@x.test', $page['Resources'][0]['userName']);
        self::assertSame(3, $counted['totalResults']);
        self::assertSame([], $counted['Resources']);
    }

    public function testTheFirstSamlSignInFindsTheAccountProvisionedForIt(): void
    {
        $this->freezeClock(Idp::NOW);
        $this->registerSaml();
        [$token] = $this->provisioningToken('acme');
        $provisioned = $this->scim('POST', self::USERS, $token, json_encode([
            'userName' => 'ada@acme.example',
            'externalId' => self::SUBJECT,
            'emails' => [['value' => 'ada@acme.example', 'primary' => true]],
        ], JSON_THROW_ON_ERROR));
        self::assertCreated($provisioned);
        $missing = $this->scim('POST', self::USERS, $token, '{"userName": "grace@acme.example"}');

        $signedIn = $this->signInThroughSaml();

        self::assertScimError(self::BAD, $missing, 'invalidValue');
        self::assertStringContainsString('externalId', (string) $missing->getBody(), 'It names the subject.');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $signedIn->getStatusCode(),
            (string) $signedIn->getBody(),
        );
        self::assertSame(
            self::document($provisioned)['id'],
            $this->session($this->cookie(self::SESSION_COOKIE))?->userId->value,
            'The provisioned account, not a second one.',
        );
        self::assertSame(1, self::rows("SELECT count(*) FROM users WHERE connection = 'acme'"));
    }

    public function testAConnectionRequiringProvisioningRefusesAnyoneElse(): void
    {
        $this->freezeClock(Idp::NOW);
        $this->registerSaml();
        $this->adminToken();
        $switched = $this->api('PATCH', '/api/v1/connections/acme', ['require_provisioning' => true]);
        self::assertTrue(self::document($switched)['require_provisioning']);

        $refused = $this->signInThroughSaml();

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertSame(0, self::rows("SELECT count(*) FROM users WHERE connection = 'acme'"), 'Nothing created.');
        self::assertStringContainsString('not_provisioned', (string) TestStorage::database()->fetchValue(
            'SELECT details::text FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::SignInFailed->value],
        ));
        $this->clearCookies();
        [$token] = $this->provisioningToken('acme');
        $this->scim('POST', self::USERS, $token, self::resource('ada@acme.example', self::SUBJECT));
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $this->signInThroughSaml()->getStatusCode(),
            'Provisioned: in.',
        );
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $this->api('PATCH', '/api/v1/connections/password', ['require_provisioning' => true])->getStatusCode(),
            'A pool does not require provisioning.',
        );
    }

    public function testEntraIdsPatchSequenceChangesTheAccount(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        [$token, $tokenId] = $this->provisioningToken('password');
        $created = $this->scim('POST', self::USERS, $token, self::ENTRA_USER);
        $id = self::document($created)['id'];
        self::assertIsString($id);
        $clock->advance(60);

        $patched = $this->scim('PATCH', self::USERS . '/' . $id, $token, self::patch(
            ['op' => 'Replace', 'path' => 'emails[type eq "work"].value', 'value' => 'ada.l@contoso.com'],
            ['op' => 'Replace', 'path' => 'name.familyName', 'value' => 'King'],
            ['op' => 'Add', 'path' => 'nickName', 'value' => 'Ada'],
        ));

        self::assertSame(StatusCodeInterface::STATUS_OK, $patched->getStatusCode(), (string) $patched->getBody());
        $user = self::document($patched);
        self::assertSame([['value' => 'ada.l@contoso.com', 'primary' => true]], $user['emails']);
        self::assertSame(['givenName' => 'Ada', 'familyName' => 'King'], $user['name']);
        self::assertSame('Ada', $user['nickName']);
        self::assertNotSame($created->getHeaderLine('ETag'), $patched->getHeaderLine('ETag'), 'A new version.');
        self::assertIsArray($user['meta']);
        self::assertSame($patched->getHeaderLine('ETag'), $user['meta']['version']);
        self::assertStringStartsWith('W/"', $user['meta']['version']);
        $event = TestStorage::database()->fetchOne(
            'SELECT actor_kind, actor_provisioning_token_id, details::text AS details FROM audit_events '
            . 'WHERE type = :type',
            ['type' => AuditEventType::UserUpdated->value],
        );
        self::assertIsArray($event);
        self::assertSame('provisioning', $event['actor_kind']);
        self::assertSame($tokenId, $event['actor_provisioning_token_id']);
        self::assertIsString($event['details']);
        self::assertStringNotContainsString('ada.l@contoso.com', $event['details'], 'What changed, never to what.');
    }

    public function testAPutReplacesTheWholeResource(): void
    {
        [$token] = $this->provisioningToken('password');
        $id = self::document($this->scim('POST', self::USERS, $token, (string) json_encode([
            'userName' => 'grace@example.com',
            'displayName' => 'Grace Hopper',
            'nickName' => 'Amazing',
        ])))['id'];
        self::assertIsString($id);

        $replaced = $this->scim('PUT', self::USERS . '/' . $id, $token, (string) json_encode([
            'userName' => 'g.hopper@example.com',
            'externalId' => 'g1',
            'name' => ['givenName' => 'Grace'],
        ]));

        self::assertSame(StatusCodeInterface::STATUS_OK, $replaced->getStatusCode(), (string) $replaced->getBody());
        $user = self::document($replaced);
        self::assertSame('g.hopper@example.com', $user['userName']);
        self::assertSame('g1', $user['externalId']);
        self::assertArrayNotHasKey('displayName', $user, 'Left out, so cleared.');
        self::assertArrayNotHasKey('nickName', $user);
        self::assertSame([['value' => 'g.hopper@example.com', 'primary' => true]], $user['emails']);
        self::assertSame(1, $this->filtered($token, 'userName eq "G.HOPPER@example.com"')['totalResults']);
    }

    public function testIfMatchKeepsADirectoryFromOverwritingAChangeItHasNotSeen(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        [$token] = $this->provisioningToken('password');
        $created = $this->scim('POST', self::USERS, $token, '{"userName": "ada@x.test"}');
        $id = self::document($created)['id'];
        self::assertIsString($id);
        $first = $created->getHeaderLine('ETag');
        $clock->advance(1);
        $this->scim('PATCH', self::USERS . '/' . $id, $token, self::patch(
            ['op' => 'add', 'path' => 'nickName', 'value' => 'Ada'],
        ));
        $nickName = self::patch(['op' => 'replace', 'path' => 'nickName', 'value' => 'Countess']);

        $stale = $this->scim('PATCH', self::USERS . '/' . $id, $token, $nickName, ['If-Match' => $first]);
        $current = $this->scim('GET', self::USERS . '/' . $id, $token)->getHeaderLine('ETag');
        $fresh = $this->scim('PATCH', self::USERS . '/' . $id, $token, $nickName, ['If-Match' => $current]);
        $any = $this->scim('DELETE', self::USERS . '/' . $id, $token, null, ['If-Match' => '*']);

        self::assertScimError(StatusCodeInterface::STATUS_PRECONDITION_FAILED, $stale);
        self::assertSame(StatusCodeInterface::STATUS_OK, $fresh->getStatusCode(), (string) $fresh->getBody());
        self::assertSame('Countess', self::document($fresh)['nickName']);
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $any->getStatusCode());
    }

    public function testADeleteDeletesTheAccountOrDeactivatesItWhenTheTokenSaysToKeepIt(): void
    {
        [$deleting, $tokenId] = $this->provisioningToken('password');
        [$keeping] = $this->provisioningToken('password', ['delete_deactivates' => true]);
        $gone = self::document($this->scim('POST', self::USERS, $deleting, '{"userName": "gone@x.test"}'))['id'];
        $kept = self::document($this->scim('POST', self::USERS, $keeping, '{"userName": "kept@x.test"}'))['id'];
        self::assertIsString($gone);
        self::assertIsString($kept);

        $deleted = $this->scim('DELETE', self::USERS . '/' . $gone, $deleting);
        $deactivated = $this->scim('DELETE', self::USERS . '/' . $kept, $keeping);

        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $deleted->getStatusCode(),
            (string) $deleted->getBody(),
        );
        $notFound = StatusCodeInterface::STATUS_NOT_FOUND;
        self::assertScimError($notFound, $this->scim('GET', self::USERS . '/' . $gone, $deleting));
        self::assertSame(0, self::rows("SELECT count(*) FROM users WHERE email = 'gone@x.test'"));
        self::assertSame($tokenId, TestStorage::database()->fetchValue(
            'SELECT actor_provisioning_token_id FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::UserDeleted->value],
        ));
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $deactivated->getStatusCode());
        self::assertFalse(self::document($this->scim('GET', self::USERS . '/' . $kept, $keeping))['active']);
        self::assertScimError($notFound, $this->scim('DELETE', self::USERS . '/' . $gone, $deleting));
    }

    public function testAChangeIsHeldToTheRulesOfACreation(): void
    {
        [$token] = $this->provisioningToken('password');
        $this->scim('POST', self::USERS, $token, '{"userName": "grace@x.test"}');
        $id = self::document($this->scim('POST', self::USERS, $token, '{"userName": "ada@x.test"}'))['id'];
        self::assertIsString($id);
        $path = self::USERS . '/' . $id;

        $rename = self::patch(['op' => 'replace', 'path' => 'userName', 'value' => 'GRACE@x.test']);
        $taken = $this->scim('PATCH', $path, $token, $rename);
        $password = $this->scim('PUT', $path, $token, '{"userName": "ada@x.test", "password": "secret"}');
        $unreadable = self::patch(['op' => 'replace', 'path' => 'emails[', 'value' => 'x']);
        $badPath = $this->scim('PATCH', $path, $token, $unreadable);
        $noTarget = $this->scim('PATCH', $path, $token, (string) json_encode(['Operations' => [['op' => 'remove']]]));

        self::assertScimError(StatusCodeInterface::STATUS_CONFLICT, $taken, 'uniqueness');
        self::assertScimError(self::BAD, $password, 'invalidValue');
        self::assertScimError(self::BAD, $badPath, 'invalidPath');
        self::assertScimError(self::BAD, $noTarget, 'noTarget');
        self::assertSame('ada@x.test', self::document($this->scim('GET', $path, $token))['userName'], 'Unchanged.');
    }

    public function testAnEnterpriseConnectionsIdentityFollowsItsSubject(): void
    {
        $this->freezeClock(Idp::NOW);
        $this->registerSaml();
        [$token] = $this->provisioningToken('acme');
        $created = $this->scim('POST', self::USERS, $token, self::resource('ada@acme.example', 'old-subject'));
        $id = self::document($created)['id'];
        self::assertIsString($id);

        $moved = $this->scim('PATCH', self::USERS . '/' . $id, $token, self::patch(
            ['op' => 'replace', 'path' => 'externalId', 'value' => self::SUBJECT],
        ));
        $removed = $this->scim('PATCH', self::USERS . '/' . $id, $token, self::patch(
            ['op' => 'remove', 'path' => 'externalId'],
        ));

        self::assertSame(StatusCodeInterface::STATUS_OK, $moved->getStatusCode(), (string) $moved->getBody());
        self::assertSame([self::SUBJECT], array_column(
            TestStorage::database()->fetchAll(
                'SELECT subject FROM external_identities WHERE user_id = :id',
                ['id' => $id],
            ),
            'subject',
        ));
        self::assertScimError(self::BAD, $removed, 'invalidValue');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $this->signInThroughSaml()->getStatusCode(),
            'By the new subject.',
        );
    }

    /** @param array<string, mixed> ...$operations */
    private static function patch(array ...$operations): string
    {
        return json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => $operations,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{0: string, 1: string} The token and its id.
     */
    private function provisioningToken(string $connection, array $options = []): array
    {
        $this->adminToken();
        $issued = $this->api('POST', '/api/v1/provisioning-tokens', $options + [
            'connection' => $connection,
            'description' => 'Directory',
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $issued->getStatusCode(), (string) $issued->getBody());
        $document = self::document($issued);
        self::assertIsString($document['token']);
        self::assertIsString($document['id']);

        return [$document['token'], $document['id']];
    }

    /** @return array<array-key, mixed> */
    private function filtered(string $token, string $filter): array
    {
        return self::document($this->scim('GET', self::USERS . '?filter=' . rawurlencode($filter), $token));
    }

    private static function resource(string $userName, ?string $externalId = null, ?string $email = null): string
    {
        return json_encode(array_filter([
            'userName' => $userName,
            'externalId' => $externalId,
            'emails' => $email === null ? null : [['value' => $email]],
        ]), JSON_THROW_ON_ERROR);
    }

    private static function rows(string $sql): int
    {
        return (int) TestStorage::database()->fetchValue($sql);
    }

    private static function assertCreated(ResponseInterface $response): void
    {
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
    }

    /** @param array<non-empty-string, string> $extra */
    private function scim(
        string $method,
        string $path,
        string $token,
        ?string $body = null,
        array $extra = [],
    ): ResponseInterface {
        $headers = ['Authorization' => 'Bearer ' . $token] + $extra;
        if ($body !== null) {
            $headers['Content-Type'] = 'application/scim+json';
        }

        return $this->request($method, $path, $headers, self::MANAGEMENT_HOST, $body ?? '');
    }

    private static function assertScimError(int $status, ResponseInterface $response, ?string $scimType = null): void
    {
        self::assertSame($status, $response->getStatusCode(), (string) $response->getBody());
        $document = self::document($response);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $document['schemas']);
        self::assertSame((string) $status, $document['status']);
        self::assertSame($scimType, $document['scimType'] ?? null);
    }

    private function registerSaml(): void
    {
        $this->adminToken();
        $created = $this->api('POST', '/api/v1/connections', [
            'name' => 'acme',
            'display_name' => 'Acme staff',
            'strategy' => 'saml',
            'is_domain_connection' => true,
            'saml' => (object) [
                'metadata' => Idp::metadata([Idp::rsa()['certificate']]),
                'email_attribute' => 'email',
            ],
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
    }

    /** The whole round trip: out to the identity provider, its response back, the sign-in completed. */
    private function signInThroughSaml(): ResponseInterface
    {
        $started = $this->get('/auth/saml/acme');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $started->getStatusCode(),
            (string) $started->getBody(),
        );
        parse_str((string) parse_url($started->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $request = new DOMDocument();
        $encoded = (string) base64_decode((string) ($query['SAMLRequest'] ?? ''), true);
        $xml = (string) gzinflate($encoded);
        if ($xml === '') {
            self::fail('No AuthnRequest.');
        }
        self::assertTrue($request->loadXML($xml));
        $id = (string) $request->documentElement?->getAttribute('ID');
        $acs = $this->post('/auth/saml/acme/acs', [
            'SAMLResponse' => Idp::response([
                'inResponseTo' => $id,
                'confirmationInResponseTo' => $id,
                'assertionId' => '_' . $id,
            ]),
            'RelayState' => (string) ($query['RelayState'] ?? ''),
        ]);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $acs->getStatusCode(), (string) $acs->getBody());

        return $this->get($acs->getHeaderLine('Location'));
    }
}
