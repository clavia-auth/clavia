<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Oidc;

use Clavia\Adapter\Secondary\Signing\Jose\JoseSignatureVerifier;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\Logout\EndSession;
use Clavia\Application\Oidc\Logout\EndSessionRequest;
use Clavia\Application\Oidc\Logout\SignedOut;
use Clavia\Application\Oidc\Logout\SignOutConfirmationNeeded;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class EndSessionTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';
    private const string SIGNED_OUT = 'https://app.example/signed-out';

    private FrozenClock $clock;
    private Sessions $sessions;
    private InMemorySigningKeys $keys;
    private InMemoryClientRepository $clients;
    private EndSession $endSession;
    private UserId $userId;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->sessions = new Sessions(
            new InMemorySessionStore($this->clock),
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            28800,
            604800,
        );
        $this->keys = new InMemorySigningKeys($this->clock);
        $this->keys->create(SigningAlgorithm::RS256, $this->clock->now());
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(self::client('spa', [self::SIGNED_OUT, 'https://app.example/bye?lang=fr']));
        $this->clients->save(self::client('other', []));
        $this->endSession = new EndSession(
            $this->sessions,
            $this->clients,
            $this->keys,
            new JoseSignatureVerifier(),
            self::ISSUER,
        );
        $this->userId = UserId::generate(new SeededRandomSource(2));
    }

    public function testAHintForTheSessionsPersonEndsItWithoutAsking(): void
    {
        $sessionId = $this->session();

        $outcome = $this->end(hint: $this->hint(), uri: self::SIGNED_OUT, state: 's 1', sessionId: $sessionId);

        self::assertEquals(new SignedOut(self::SIGNED_OUT . '?state=s%201', true), $outcome);
        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testStateJoinsAQueryTheUriAlreadyHas(): void
    {
        $outcome = $this->end(
            hint: $this->hint(),
            uri: 'https://app.example/bye?lang=fr',
            state: 'x',
            sessionId: $this->session(),
        );

        self::assertInstanceOf(SignedOut::class, $outcome);
        self::assertSame('https://app.example/bye?lang=fr&state=x', $outcome->location);
    }

    public function testWithoutProofThePersonIsAskedAndOnlyCheckedValuesAreCarried(): void
    {
        $sessionId = $this->session();

        $outcome = $this->end(clientId: 'spa', uri: self::SIGNED_OUT, state: 'x', sessionId: $sessionId);

        self::assertInstanceOf(SignOutConfirmationNeeded::class, $outcome);
        self::assertEquals(new SignOutConfirmationNeeded('spa', 'A public client', self::SIGNED_OUT, 'x'), $outcome);
        self::assertSame('https://app.example', $outcome->destinationOrigin());
        self::assertNotNull($this->sessions->resolve($sessionId));

        $unregistered = $this->end(clientId: 'spa', uri: 'https://evil.example/', state: 'x', sessionId: $sessionId);
        self::assertEquals(new SignOutConfirmationNeeded('spa', 'A public client', null, null), $unregistered);
    }

    public function testTheConfirmationEndsTheSession(): void
    {
        $sessionId = $this->session();

        $outcome = $this->end(clientId: 'spa', uri: self::SIGNED_OUT, confirmed: true, sessionId: $sessionId);

        self::assertEquals(new SignedOut(self::SIGNED_OUT, true), $outcome);
        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testAHintFromAnotherIssuerOrForAnotherPersonProvesNothing(): void
    {
        $sessionId = $this->session();

        $hints = [
            $this->hint(['iss' => 'https://other.example']),
            $this->hint(['sub' => UserId::generate(new SeededRandomSource(3))->value]),
            $this->hint(['sub' => null]),
        ];

        foreach ($hints as $hint) {
            self::assertInstanceOf(SignOutConfirmationNeeded::class, $this->end(hint: $hint, sessionId: $sessionId));
        }
        self::assertNotNull($this->sessions->resolve($sessionId));
    }

    public function testAClientIdContradictingTheHintVoidsTheProofAndTheDestination(): void
    {
        $sessionId = $this->session();

        $outcome = $this->end(hint: $this->hint(), clientId: 'other', uri: self::SIGNED_OUT, sessionId: $sessionId);

        self::assertEquals(new SignOutConfirmationNeeded(null, null, null, null), $outcome);
    }

    public function testTheHintsAudienceIdentifiesTheApplication(): void
    {
        foreach ([['aud' => 'spa'], ['aud' => ['spa']], ['aud' => ['spa', 'api'], 'azp' => 'spa']] as $claims) {
            $outcome = $this->end(hint: $this->hint($claims), uri: self::SIGNED_OUT);

            self::assertEquals(new SignedOut(self::SIGNED_OUT, false), $outcome, (string) json_encode($claims));
        }
    }

    public function testWithoutASessionNothingEndsAndOnlyARegisteredUriIsFollowed(): void
    {
        self::assertEquals(new SignedOut(self::SIGNED_OUT, false), $this->end(clientId: 'spa', uri: self::SIGNED_OUT));
        self::assertEquals(new SignedOut('/auth/login', false), $this->end(uri: self::SIGNED_OUT));
        self::assertEquals(new SignedOut('/auth/login', false), $this->end(clientId: 'nobody', uri: self::SIGNED_OUT));
        self::assertEquals(
            new SignedOut('/auth/login', false),
            $this->end(clientId: 'not an id', uri: self::SIGNED_OUT),
        );
        self::assertEquals(new SignedOut('/auth/login', false), $this->end(clientId: 'spa'));
    }

    public function testAPostLogoutUriWithAFragmentCannotBeRegistered(): void
    {
        $this->expectException(InvalidValue::class);

        self::client('x', ['https://app.example/bye#top']);
    }

    private function end(
        ?string $hint = null,
        ?string $clientId = null,
        ?string $uri = null,
        ?string $state = null,
        bool $confirmed = false,
        ?string $sessionId = null,
    ): SignedOut|SignOutConfirmationNeeded {
        return ($this->endSession)(new EndSessionRequest($hint, $clientId, $uri, $state, $confirmed, $sessionId));
    }

    private function session(): string
    {
        return $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
    }

    /**
     * An ID token this server signed, with claims replaced or (null) removed.
     *
     * @param array<non-empty-string, mixed> $overrides
     */
    private function hint(array $overrides = []): string
    {
        $claims = array_filter(
            $overrides + ['iss' => self::ISSUER, 'sub' => $this->userId->value, 'aud' => 'spa', 'exp' => 1],
            static fn (mixed $value): bool => $value !== null,
        );

        return new CompactJws($this->keys)->sign($this->keys->activeKey(), $claims);
    }

    /**
     * @param list<string> $postLogoutRedirectUris
     */
    private static function client(string $id, array $postLogoutRedirectUris): Client
    {
        return Client::register(
            ClientId::fromString($id),
            'A public client',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://app.example/callback')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new \DateTimeImmutable('2026-01-15T09:00:00Z'),
            array_map(Url::fromString(...), $postLogoutRedirectUris),
        );
    }
}
