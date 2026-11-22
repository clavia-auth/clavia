<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Mfa;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Mfa\CompletePasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\PasskeySecondFactorAttempt;
use Clavia\Application\Authentication\Mfa\SecondFactorRejected;
use Clavia\Application\Authentication\Passkey\UsePasskey;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Port\VerifiedAssertion;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasskeyVerifier;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\InMemoryWebAuthnChallengeStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * A passkey as the second factor, with the verifier told to accept: what the use case itself
 * decides, apart from whether the response is genuine.
 */
final class CompletePasskeySecondFactorTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryMfaChallengeStore $challenges;
    private InMemoryWebAuthnChallengeStore $ceremonies;
    private User $user;
    private Passkey $passkey;
    private CompletePasskeySecondFactor $complete;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->challenges = new InMemoryMfaChallengeStore($this->clock);
        $this->ceremonies = new InMemoryWebAuthnChallengeStore($this->clock);
        $users = new InMemoryUserRepository();
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'ada@example.com',
            'h',
            $this->clock->now(),
        );
        $users->save($this->user);
        $passkeys = new InMemoryPasskeyRepository();
        $this->passkey = Passkey::register(
            PasskeyId::generate(new SeededRandomSource(2)),
            $this->user->id,
            CredentialId::fromBytes(str_repeat("\x04", 16)),
            CosePublicKey::fromBytes('k'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString('Key'),
            $this->clock->now(),
        );
        $passkeys->save($this->passkey);
        $verifier = new FakePasskeyVerifier();
        $verifier->acceptAssertionsAs(new VerifiedAssertion(1, false, false, true));
        $events = new InMemoryDomainEvents();
        $this->complete = new CompletePasskeySecondFactor(
            $this->challenges,
            $this->ceremonies,
            $users,
            new UsePasskey(
                $passkeys,
                $verifier,
                RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test'),
                $this->clock,
                $events,
            ),
            new LoginThrottle(new InMemoryAttemptCounter($this->clock), 5, 900),
            new Sessions(
                new InMemorySessionStore($this->clock),
                new SecretGenerator(new SeededRandomSource(3)),
                $this->clock,
                28800,
                604800,
                $events,
            ),
            $this->clock,
            5,
            $events,
        );
    }

    public function testAPasskeyAfterAPasswordFinishesTheSignIn(): void
    {
        $answer = $this->answerAfter([AuthenticationMethod::Password]);

        self::assertInstanceOf(SignedIn::class, ($this->complete)($answer));
    }

    public function testAPasskeyAfterAPasskeyIsOneFactorCountedTwiceAndIsRefused(): void
    {
        foreach ([AuthenticationMethod::HardwareKey, AuthenticationMethod::SoftwareKey] as $first) {
            self::assertInstanceOf(
                SecondFactorRejected::class,
                ($this->complete)($this->answerAfter([$first])),
                $first->value,
            );
        }
    }

    /**
     * A second-factor challenge after `$firstFactor`, and a live ceremony bound to it.
     *
     * @param list<AuthenticationMethod> $firstFactor
     */
    private function answerAfter(array $firstFactor): PasskeySecondFactorAttempt
    {
        $handle = 'mfa-' . $firstFactor[0]->value;
        $this->challenges->open(
            $handle,
            new MfaChallenge($this->user->id, '/next', null, $firstFactor, ConnectionName::defaultPool()),
            300,
        );
        $this->ceremonies->open(
            'ceremony-' . $handle,
            WebAuthnChallenge::forSecondFactor(
                new SeededRandomSource(4),
                $this->user->id,
                $handle,
                $this->clock->now(),
                300,
            ),
            300,
        );

        return new PasskeySecondFactorAttempt(
            $handle,
            'ceremony-' . $handle,
            '{"id":"' . $this->passkey->credentialId->toBase64Url() . '"}',
            '192.0.2.1',
        );
    }
}
