<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\PageRequest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use DateTimeImmutable;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;

/**
 * A user's passkeys in the Management API (docs/design/passkeys.md §9): listed without their
 * credential, removed one by one, and counted on the user. Every response is checked against the
 * OpenAPI document.
 */
final class ManagementPasskeysTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    public function testAUsersPasskeysAreListedWithoutTheirCredential(): void
    {
        $user = $this->user();
        $passkey = $this->passkeyOf($user, 'Work laptop', synced: true);
        $this->adminToken();

        $response = $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users/' . $user->id->value . '/passkeys');

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame([[
            'id' => $passkey->id->value,
            'name' => 'Work laptop',
            'synced' => true,
            'backed_up' => true,
            'aaguid' => 'adce0002-35bc-c60a-648b-0b25f1f05503',
            'created_at' => '2026-01-15T10:00:00Z',
            'last_used_at' => null,
        ]], self::document($response));
        self::assertStringNotContainsString($passkey->credentialId->toBase64Url(), (string) $response->getBody());
    }

    public function testAUserIsCountedAndEnrolledByTheirPasskeys(): void
    {
        $user = $this->user();
        $this->adminToken();
        $before = self::document($this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users/' . $user->id->value));

        $this->passkeyOf($user, 'One');
        $this->passkeyOf($user, 'Two');
        $after = self::document($this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users/' . $user->id->value));

        self::assertSame(0, $before['passkey_count']);
        self::assertFalse($before['mfa_enrolled']);
        self::assertSame(2, $after['passkey_count']);
        self::assertTrue($after['mfa_enrolled']);
        $listed = self::document(
            $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users', query: ['q' => self::TEST_USER_EMAIL]),
        );
        self::assertSame(2, $listed['items'][0]['passkey_count'] ?? null);
    }

    public function testAnOperatorRemovesAPasskeyAndIsRecordedAsItsActor(): void
    {
        $user = $this->user();
        $passkey = $this->passkeyOf($user, 'Lost phone');
        $this->adminToken();

        $removed = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            '/api/v1/users/' . $user->id->value . '/passkeys/' . $passkey->id->value,
        );

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $removed->getStatusCode());
        self::assertSame([], $this->container()->get(PasskeyRepository::class)->ofUser($user->id));
        $events = $this->container()->get(AuditLog::class)->page(
            new AuditQuery(types: [AuditEventType::PasskeyRemoved]),
            PageRequest::of(1, 10),
        )->items;
        self::assertCount(1, $events);
        self::assertSame(ActorKind::Application, $events[0]->actor->kind);
        self::assertTrue($events[0]->details['by_operator'] ?? null);
        self::assertSame('Lost phone', $events[0]->details['name'] ?? null);
    }

    public function testAPasskeyOfAnotherUserOrNoneIsNotFound(): void
    {
        $user = $this->user();
        $other = $this->otherUser();
        $theirs = $this->passkeyOf($other, 'Theirs');
        $this->adminToken();

        $wrongAccount = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            '/api/v1/users/' . $user->id->value . '/passkeys/' . $theirs->id->value,
        );
        $none = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            '/api/v1/users/' . $user->id->value . '/passkeys/00000000-0000-4000-8000-000000000009',
        );
        $noUser = $this->api(
            RequestMethodInterface::METHOD_GET,
            '/api/v1/users/00000000-0000-4000-8000-000000000009/passkeys',
        );

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $wrongAccount->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $none->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $noUser->getStatusCode());
        self::assertCount(1, $this->container()->get(PasskeyRepository::class)->ofUser($other->id));
    }

    public function testListingNeedsReadUsersAndRemovingNeedsUpdateUsers(): void
    {
        $user = $this->user();
        $passkey = $this->passkeyOf($user, 'Key');
        $this->adminToken(['read:users']);

        $list = $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users/' . $user->id->value . '/passkeys');
        $remove = $this->api(
            RequestMethodInterface::METHOD_DELETE,
            '/api/v1/users/' . $user->id->value . '/passkeys/' . $passkey->id->value,
        );

        self::assertSame(StatusCodeInterface::STATUS_OK, $list->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $remove->getStatusCode());
        self::assertCount(1, $this->container()->get(PasskeyRepository::class)->ofUser($user->id));
    }

    private function passkeyOf(User $user, string $name, bool $synced = false): Passkey
    {
        $passkey = Passkey::register(
            PasskeyId::generate(new SeededRandomSource(crc32($name))),
            $user->id,
            CredentialId::fromBytes(hash('sha256', $name, true)),
            CosePublicKey::fromBytes("\xa5\x01"),
            CoseAlgorithm::ES256,
            0,
            [],
            Aaguid::fromString('adce0002-35bc-c60a-648b-0b25f1f05503'),
            $synced,
            $synced,
            PasskeyName::fromString($name),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->container()->get(PasskeyRepository::class)->save($passkey);

        return $passkey;
    }

    private function otherUser(): User
    {
        $other = User::register(
            UserId::generate(new SeededRandomSource(77)),
            'other@clavia.dev',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->container()->get(UserRepository::class)->save($other);

        return $other;
    }
}
