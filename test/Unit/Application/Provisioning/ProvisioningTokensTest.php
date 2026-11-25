<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Provisioning;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\ProvisioningTokens\IssueProvisioningToken;
use Clavia\Application\Management\ProvisioningTokens\NewProvisioningToken;
use Clavia\Application\Management\ProvisioningTokens\ReadProvisioningTokens;
use Clavia\Application\Management\ProvisioningTokens\RevokeProvisioningToken;
use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\Provisioning\AuthenticateProvisioningToken;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Provisioning\Event\ProvisioningTokenIssued;
use Clavia\Domain\Provisioning\Event\ProvisioningTokenRevoked;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryProvisioningTokenRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** docs/design/scim-provisioning.md §5.1, §5.2, §7. */
final class ProvisioningTokensTest extends TestCase
{
    private const string ADDRESS = '203.0.113.7';

    private InMemoryProvisioningTokenRepository $tokens;
    private InMemoryConnectionRepository $connections;
    private InMemoryAttemptCounter $counter;
    private FrozenClock $clock;
    private InMemoryDomainEvents $events;
    private int $seed = 0;

    #[\Override]
    protected function setUp(): void
    {
        $this->tokens = new InMemoryProvisioningTokenRepository();
        $this->connections = new InMemoryConnectionRepository();
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->counter = new InMemoryAttemptCounter($this->clock);
        $this->events = new InMemoryDomainEvents();
    }

    public function testTheSecretIsHandedOutOnceAndKeptAsItsDigest(): void
    {
        $issued = $this->issue()(
            new NewProvisioningToken('password', 'Entra ID', subjectAttribute: SubjectAttribute::UserName),
        );

        self::assertSame(43, strlen($issued->secret));
        self::assertTrue($issued->token->digest->equals(Digest::of($issued->secret)));
        self::assertSame('password', $issued->token->connection->value);
        self::assertSame(SubjectAttribute::UserName, $issued->token->subjectAttribute);
        self::assertNotNull($this->tokens->findByDigest(Digest::of($issued->secret)));
        self::assertCount(1, $this->events->ofType(ProvisioningTokenIssued::class));
    }

    /** @return iterable<string, array{string}> */
    public static function connectionsNoDirectoryProvisions(): iterable
    {
        yield 'a social provider' => ['google'];
        yield 'passwordless' => ['email'];
        yield 'unknown' => ['nowhere'];
        yield 'not even a name' => ['Not A Name'];
    }

    #[DataProvider('connectionsNoDirectoryProvisions')]
    public function testOnlyAPoolOrAnEnterpriseConnectionIsProvisioned(string $connection): void
    {
        try {
            $this->issue()(new NewProvisioningToken($connection, 'Entra ID'));
            self::fail('Issued.');
        } catch (InvalidValue $refusal) {
            self::assertStringNotContainsString($connection, $refusal->getMessage(), 'Never the value sent.');
        }
        self::assertSame(0, $this->tokens->page(PageRequest::of())->total);
        self::assertSame([], $this->events->ofType(ProvisioningTokenIssued::class));
    }

    public function testARevocationIsRecordedOnce(): void
    {
        $issued = $this->issue()(new NewProvisioningToken('password', 'Entra ID'));
        $revoke = new RevokeProvisioningToken($this->tokens, $this->clock, $this->events);

        $revoke($issued->token->id);
        $revoke($issued->token->id);

        self::assertNotNull($this->tokens->find($issued->token->id)?->revokedAt);
        self::assertCount(1, $this->events->ofType(ProvisioningTokenRevoked::class));
        $this->expectException(NotFound::class);
        $revoke(ProvisioningTokenId::generate(new SeededRandomSource(99)));
    }

    public function testTheListIsByConnection(): void
    {
        $this->issue()(new NewProvisioningToken('password', 'Entra ID'));
        $read = new ReadProvisioningTokens($this->tokens, $this->clock);

        self::assertSame(1, $read->page(PageRequest::of(), 'password')->total);
        self::assertSame(0, $read->page(PageRequest::of(), 'google')->total);
        self::assertSame(0, $read->page(PageRequest::of(), 'Not A Name')->total, 'Not a name: nothing.');
    }

    public function testAUsableTokenNamesItsDirectoryAndItsConnection(): void
    {
        $issued = $this->issue()(new NewProvisioningToken('password', 'Entra ID'));

        $caller = $this->authenticate()($issued->secret, self::ADDRESS);

        self::assertNotNull($caller);
        self::assertSame('password', $caller->connection->name->value);
        self::assertSame(ActorKind::Provisioning, $caller->actor()->kind);
        self::assertTrue($caller->actor()->provisioningTokenId?->equals($issued->token->id));
    }

    public function testUnknownExpiredAndRevokedTokensAreOneRefusalAndEachCounts(): void
    {
        $expired = $this->issue()(new NewProvisioningToken('password', 'Old', 86_400));
        $revoked = $this->issue()(new NewProvisioningToken('password', 'Revoked'));
        (new RevokeProvisioningToken($this->tokens, $this->clock, $this->events))($revoked->token->id);
        $this->clock->advance(86_400);

        foreach (['not-a-token', $expired->secret, $revoked->secret] as $secret) {
            self::assertNull($this->authenticate()($secret, self::ADDRESS));
        }

        self::assertSame(3, $this->counter->count('oauth-address:' . self::ADDRESS));
    }

    public function testPastTheLimitEvenAGoodTokenIsRefusedBeforeAnyLookup(): void
    {
        $issued = $this->issue()(new NewProvisioningToken('password', 'Entra ID'));
        $authenticate = $this->authenticate();
        foreach ([1, 2, 3] as $attempt) {
            self::assertNull($authenticate('wrong-' . $attempt, self::ADDRESS));
        }

        try {
            (void) $authenticate($issued->secret, self::ADDRESS);
            self::fail('Not throttled.');
        } catch (TooManyFailedRequests $refusal) {
            self::assertSame(300, $refusal->retryAfter);
        }
        self::assertNotNull($authenticate($issued->secret, '198.51.100.1'), 'Another address is not concerned.');
    }

    public function testAGoodTokenIsNeverCounted(): void
    {
        $issued = $this->issue()(new NewProvisioningToken('password', 'Entra ID'));

        foreach (range(1, 10) as $request) {
            self::assertNotNull($this->authenticate()($issued->secret, self::ADDRESS));
        }

        self::assertSame(0, $this->counter->count('oauth-address:' . self::ADDRESS));
    }

    public function testATokenWhoseConnectionIsGoneIsRefusedWithoutCounting(): void
    {
        $issued = $this->issue()(new NewProvisioningToken('password', 'Entra ID'));
        $this->connections->delete(ConnectionName::fromString('password'));

        self::assertNull($this->authenticate()($issued->secret, self::ADDRESS));
        self::assertSame(0, $this->counter->count('oauth-address:' . self::ADDRESS), 'A genuine token, not a guess.');
    }

    private function issue(): IssueProvisioningToken
    {
        $random = new SeededRandomSource(++$this->seed);

        return new IssueProvisioningToken(
            $this->tokens,
            $this->connections,
            new SecretGenerator($random),
            $random,
            $this->clock,
            $this->events,
        );
    }

    private function authenticate(): AuthenticateProvisioningToken
    {
        return new AuthenticateProvisioningToken(
            $this->tokens,
            $this->connections,
            new ClientFailureThrottle($this->counter, 3, 300),
            $this->clock,
        );
    }
}
