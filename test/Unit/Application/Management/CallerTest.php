<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use ClaviaTest\Support\Fake\FakeDpopProofVerifier;
use ClaviaTest\Support\Fake\InMemoryDpopNonces;
use ClaviaTest\Support\Fake\InMemoryDpopReplayCache;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Application\OAuth2\ProtectedResource\PresentedCredentials;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\BearerErrorCode;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccessTokenRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Who is calling the Management API, and what they may do there.
 */
final class CallerTest extends TestCase
{
    private const string URL = 'https://management.clavia.test/api/v1/users';

    private const string MANAGEMENT_API = 'https://management.clavia.test/api/v1/';

    private InMemoryAccessTokenRepository $tokens;
    private InMemoryUserRepository $users;
    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->users = new InMemoryUserRepository();
        $this->clock = new FrozenClock();
    }

    public function testAMachineTokenForTheApiIsACallerWithItsScopes(): void
    {
        $this->issue('token', self::MANAGEMENT_API, 'read:users read:clients');

        $caller = $this->authenticate()(PresentedCredentials::bearer('token'), 'GET', self::URL);

        self::assertTrue($caller->isClient(ClientId::fromString('machine')));
        self::assertNull($caller->userId);
        self::assertEqualsCanonicalizing(['read:users', 'read:clients'], $caller->scopes->toList());
    }

    public function testATokenForAnotherApiIsInvalidWhateverItsScopes(): void
    {
        // Audience before scope: `read:users` on another API is another permission.
        $this->issue('token', 'https://elsewhere.test/', 'read:users');

        $this->assertRefused('token');
    }

    public function testAnUnknownExpiredOrRevokedTokenIsInvalid(): void
    {
        $this->assertRefused('unknown');

        $this->issue('expiring', self::MANAGEMENT_API, 'read:users');
        $this->clock->advance(3601);
        $this->assertRefused('expiring');
    }

    public function testAUsersTokenIsInvalidOnceTheUserIsDeactivatedOrGone(): void
    {
        $id = UserId::generate(new SeededRandomSource(1));
        $user = User::register($id, 'ada@example.com', null, $this->clock->now());
        $this->users->save($user);
        $this->issue('token', self::MANAGEMENT_API, 'read:users', $user->id);

        $caller = $this->authenticate()(PresentedCredentials::bearer('token'), 'GET', self::URL);

        self::assertTrue($caller->isActingAs($user->id));

        $user->deactivate($this->clock->now());
        $this->users->save($user);
        $this->assertRefused('token');

        $this->users->delete($user->id);
        $this->assertRefused('token');
    }

    public function testAMissingScopeIsInsufficientAndNamesTheOneNeeded(): void
    {
        $caller = new ManagementCaller(ClientId::fromString('machine'), null, ScopeSet::fromString('read:clients'));
        $caller->require(ManagementPermission::ReadClients);

        try {
            $caller->require(ManagementPermission::ReadUsers);
            self::fail('The scope was not required.');
        } catch (BearerTokenError $refusal) {
            self::assertSame(BearerErrorCode::InsufficientScope, $refusal->error);
            self::assertSame('read:users', $refusal->requiredScope?->toString());
        }
    }

    public function testEveryPermissionDescribesWhatItAllows(): void
    {
        foreach (ManagementPermission::cases() as $permission) {
            self::assertMatchesRegularExpression('/^(read|create|update|delete):[a-z_]+$/D', $permission->value);
            self::assertNotSame('', $permission->description());
        }
    }

    private function issue(string $token, string $audience, string $scope, ?UserId $user = null): void
    {
        $now = $this->clock->now();
        $this->tokens->add(AccessToken::reconstitute(
            AccessTokenId::generate(new SeededRandomSource(strlen($token))),
            Digest::of($token),
            ClientId::fromString('machine'),
            $user,
            null,
            Audience::fromString($audience),
            ScopeSet::fromString($scope),
            $now,
            $now->modify('+1 hour'),
            null,
        ));
    }

    /**
     * @param non-empty-string $token
     */
    private function assertRefused(string $token): void
    {
        try {
            $this->authenticate()(PresentedCredentials::bearer($token), 'GET', self::URL);
            self::fail('The token was accepted.');
        } catch (BearerTokenError $refusal) {
            self::assertSame(BearerErrorCode::InvalidToken, $refusal->error);
        }
    }

    private function authenticate(): AuthenticateManagementCaller
    {
        return new AuthenticateManagementCaller(
            $this->tokens,
            $this->users,
            $this->clock,
            Audience::fromString(self::MANAGEMENT_API),
            new InMemoryResourceServerRepository(),
            self::senderConstraint(),
        );
    }

    private static function senderConstraint(): CheckSenderConstraint
    {
        $clock = new FrozenClock();

        return new CheckSenderConstraint(new ReadDpopProof(
            new FakeDpopProofVerifier(),
            new InMemoryDpopReplayCache($clock),
            new InMemoryDpopNonces($clock),
            $clock,
            60,
        ));
    }
}
