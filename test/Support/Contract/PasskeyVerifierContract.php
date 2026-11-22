<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\VerifiedRegistration;
use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\SoftwareAuthenticator;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see PasskeyVerifier} must do, shown with a {@see SoftwareAuthenticator}: genuine
 * responses, signed by real keys, are accepted; and a response with any one thing wrong — the
 * origin, the relying party, the challenge, the type, a flag, the signature, the key, the
 * account, the purpose — is refused (WebAuthn Level 3 §7.1 and §7.2).
 */
trait PasskeyVerifierContract
{
    abstract protected function verifier(): PasskeyVerifier;

    // ── Registration ──────────────────────────────────────────────────────────────────────────

    /** @return iterable<string, array{CoseAlgorithm}> */
    public static function algorithms(): iterable
    {
        yield 'EdDSA' => [CoseAlgorithm::EdDSA];
        yield 'ES256' => [CoseAlgorithm::ES256];
        yield 'RS256' => [CoseAlgorithm::RS256];
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function aGenuineRegistrationYieldsTheCredentialItMade(CoseAlgorithm $algorithm): void
    {
        $authenticator = SoftwareAuthenticator::generate($algorithm);
        $challenge = $this->registration();

        $verified = $this->verifier()->verifyRegistration(
            $authenticator->register($challenge, $this->rp()),
            $challenge,
            $this->rp(),
        );

        self::assertSame($authenticator->credentialId, $verified->credentialId->bytes());
        self::assertSame($authenticator->coseKey, $verified->publicKey->bytes());
        self::assertSame($algorithm, $verified->algorithm);
        self::assertSame(0, $verified->signCount);
        self::assertSame([Transport::Internal, Transport::Hybrid], $verified->transports);
        self::assertNull($verified->aaguid);
        self::assertFalse($verified->backupEligible);
        self::assertFalse($verified->backedUp);
        self::assertTrue($verified->userVerified);
    }

    #[Test]
    public function aSyncedPasskeyIsReportedAsEligibleAndBackedUpAndKeepsItsMake(): void
    {
        $make = Aaguid::fromString('adce0002-35bc-c60a-648b-0b25f1f05503');
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256, synced: true, aaguid: $make);
        $challenge = $this->registration();

        $verified = $this->verifier()->verifyRegistration(
            $authenticator->register($challenge, $this->rp(), transports: ['usb', 'smart-card', 'usb']),
            $challenge,
            $this->rp(),
        );

        self::assertTrue($verified->backupEligible);
        self::assertTrue($verified->backedUp);
        self::assertTrue($verified->aaguid?->equals($make));
        self::assertSame([Transport::Usb], $verified->transports, 'A transport Clavia does not know is dropped.');
    }

    #[Test]
    public function aDeviceBoundPasskeyMayBeEligibleWithoutBeingBackedUpYet(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA);
        $challenge = $this->registration();

        $verified = $this->verifier()->verifyRegistration(
            $authenticator->register($challenge, $this->rp(), backupEligible: true, backedUp: false),
            $challenge,
            $this->rp(),
        );

        self::assertTrue($verified->backupEligible);
        self::assertFalse($verified->backedUp);
    }

    /**
     * What breaks, as the named arguments of {@see SoftwareAuthenticator::register()}, and what the
     * refusal must say.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function badRegistrations(): iterable
    {
        yield 'another challenge' => [['challengeBytes' => str_repeat("\x01", 32)], 'challenge'];
        yield 'another subdomain' => [['origin' => 'https://evil.auth.clavia.test'], 'origin'];
        yield 'another site' => [['origin' => 'https://auth.clavia.test.evil.example'], 'origin'];
        yield 'plain http' => [['origin' => 'http://auth.clavia.test'], 'origin'];
        yield 'another port' => [['origin' => 'https://auth.clavia.test:8443'], 'origin'];
        yield 'another relying party id' => [['rpId' => 'evil.example'], 'rpId hash'];
        yield 'an authentication type' => [['type' => 'webauthn.get'], 'type'];
        yield 'nobody present' => [['userPresent' => false], 'not present'];
        yield 'nobody verified' => [['userVerified' => false], 'authentication required'];
        yield 'backed up without being eligible' => [['backupEligible' => false, 'backedUp' => true], 'backup'];
        yield 'an algorithm that is not offered' => [['coseAlgorithm' => -35], 'algorithm'];
        yield 'an attestation format it does not know' => [
            ['attestationFormat' => 'packed'],
            'not a WebAuthn credential',
        ];
    }

    /**
     * @param array<string, mixed> $tamper
     *
     * @psalm-suppress MixedArgument The provider's array is the named arguments of the call.
     */
    #[Test]
    #[DataProvider('badRegistrations')]
    public function aRegistrationWithOneThingWrongIsRefusedForThatReason(array $tamper, string $reason): void
    {
        $challenge = $this->registration();

        try {
            $this->verifier()->verifyRegistration(
                SoftwareAuthenticator::generate(CoseAlgorithm::ES256)->register($challenge, $this->rp(), ...$tamper),
                $challenge,
                $this->rp(),
            );
            self::fail('A response with ' . $reason . ' wrong was accepted.');
        } catch (PasskeyRejected $rejected) {
            self::assertStringContainsStringIgnoringCase($reason, $rejected->getMessage());
        }
    }

    #[Test]
    public function aRegistrationAnswersOnlyAChallengeMadeToRegister(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $signIn = WebAuthnChallenge::forSignIn(new SeededRandomSource(5), 'login-state', $this->now(), 300);

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyRegistration(
            $authenticator->register($signIn, $this->rp()),
            $signIn,
            $this->rp(),
        );
    }

    #[Test]
    public function anAuthenticationIsNotARegistration(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $challenge = $this->registration();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyRegistration(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner()),
            $challenge,
            $this->rp(),
        );
    }

    #[Test]
    #[DataProvider('notACredential')]
    public function whatIsNotAWebAuthnResponseIsRefused(string $json): void
    {
        $challenge = $this->registration();

        try {
            $this->verifier()->verifyRegistration($json, $challenge, $this->rp());
            self::fail('Garbage was accepted as a registration.');
        } catch (PasskeyRejected $rejected) {
            self::assertNotSame('', $rejected->getMessage());
        }

        $this->expectException(PasskeyRejected::class);
        $this->verifier()->credentialIdOf($json);
    }

    /** @return iterable<string, array{string}> */
    public static function notACredential(): iterable
    {
        yield 'nothing' => [''];
        yield 'not JSON' => ['{not json'];
        yield 'an empty object' => ['{}'];
        yield 'a list' => ['[]'];
        yield 'a string' => ['"credential"'];
        yield 'no response' => ['{"id":"AAAA","rawId":"AAAA","type":"public-key"}'];
        yield 'the wrong type' => ['{"id":"AAAA","rawId":"AAAA","type":"password","response":{}}'];
        yield 'too large' => ['{"id":"' . str_repeat('A', 70000) . '"}'];
    }

    #[Test]
    public function theCredentialIdIsReadWithoutVerifyingAnything(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA);
        $challenge = $this->registration();

        $fromRegistration = $this->verifier()->credentialIdOf($authenticator->register($challenge, $this->rp()));
        // Even a response that would be refused names its credential: looking the passkey up comes first.
        $fromTamperedAuthentication = $this->verifier()->credentialIdOf(
            $authenticator->authenticate(
                $challenge,
                $this->rp(),
                null,
                origin: 'https://evil.example',
                flipSignature: true,
            ),
        );

        self::assertSame($authenticator->credentialId, $fromRegistration->bytes());
        self::assertSame($authenticator->credentialId, $fromTamperedAuthentication->bytes());
    }

    #[Test]
    public function aCredentialIdOutsideTheSpecificationsBoundsIsRefused(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA, credentialId: 'short');

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->credentialIdOf($authenticator->register($this->registration(), $this->rp()));
    }

    // ── Authentication ────────────────────────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('algorithms')]
    public function aGenuineSignInIsVerifiedWithTheCountersAndFlagsItCarries(CoseAlgorithm $algorithm): void
    {
        $authenticator = SoftwareAuthenticator::generate($algorithm);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        $verified = $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner(), signCount: 9),
            $challenge,
            $this->rp(),
            $passkey,
        );

        self::assertSame(9, $verified->signCount);
        self::assertTrue($verified->userVerified);
        self::assertFalse($verified->backupEligible);
        self::assertFalse($verified->backedUp);
    }

    #[Test]
    public function aSyncedPasskeyReportsItsBackupStateAndANonCountingOneReportsZero(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256, synced: true);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        $verified = $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner(), signCount: 0),
            $challenge,
            $this->rp(),
            $passkey,
        );

        self::assertSame(0, $verified->signCount);
        self::assertTrue($verified->backupEligible);
        self::assertTrue($verified->backedUp);
    }

    #[Test]
    public function theCounterIsReportedNotJudged(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA);
        $passkey = $this->passkeyOf($authenticator);
        $passkey->recordUse(50, false, $this->now());
        $challenge = $this->signIn();

        $verified = $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner(), signCount: 3),
            $challenge,
            $this->rp(),
            $passkey,
        );

        self::assertSame(3, $verified->signCount, 'Whether it grew is the passkey\'s rule, not the verifier\'s.');
    }

    #[Test]
    public function aSecondFactorNeedsOnlyPresenceAndReportsThatNobodyWasVerified(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->secondFactor();

        $verified = $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner(), userVerified: false),
            $challenge,
            $this->rp(),
            $passkey,
        );

        self::assertFalse($verified->userVerified);
    }

    #[Test]
    public function aSecondFactorMayLeaveTheUserHandleOut(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->secondFactor();

        $verified = $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), null),
            $challenge,
            $this->rp(),
            $passkey,
        );

        self::assertSame(1, $verified->signCount);
    }

    /**
     * What breaks, as the named arguments of {@see SoftwareAuthenticator::authenticate()}, and what the
     * refusal must say.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function badAuthentications(): iterable
    {
        yield 'another challenge' => [['challengeBytes' => str_repeat("\x01", 32)], 'challenge'];
        yield 'another subdomain' => [['origin' => 'https://evil.auth.clavia.test'], 'origin'];
        yield 'another site' => [['origin' => 'https://evil.example'], 'origin'];
        yield 'plain http' => [['origin' => 'http://auth.clavia.test'], 'origin'];
        yield 'another relying party id' => [['rpId' => 'evil.example'], 'rpId hash'];
        yield 'a registration type' => [['type' => 'webauthn.create'], 'type'];
        yield 'nobody present' => [['userPresent' => false], 'not present'];
        yield 'a signature with a bit wrong' => [['flipSignature' => true], 'signature'];
        yield 'a signature by another key' => [['signWithAnotherKey' => true], 'signature'];
        yield 'authenticator data changed after signing' => [
            ['userVerified' => false, 'tamperAfterSigning' => true],
            'signature',
        ];
        yield 'another credential' => [['credentialId' => str_repeat("\x09", 32)], 'another credential'];
        yield 'a backup eligibility that changed' => [['backupEligible' => true], 'backup eligibility'];
        yield 'a backup state without eligibility' => [['backupEligible' => false, 'backedUp' => true], 'backup'];
        yield 'the account of somebody else' => [
            ['userHandle' => UserId::generate(new SeededRandomSource(99))],
            'user handle',
        ];
    }

    /**
     * @param array<string, mixed> $tamper
     *
     * @psalm-suppress MixedArgument The provider's array is the named arguments of the call.
     */
    #[Test]
    #[DataProvider('badAuthentications')]
    public function aSignInWithOneThingWrongIsRefusedForThatReason(array $tamper, string $reason): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        try {
            $this->verifier()->verifyAssertion(
                $authenticator->authenticate($challenge, $this->rp(), ...['userHandle' => $this->owner(), ...$tamper]),
                $challenge,
                $this->rp(),
                $passkey,
            );
            self::fail('A response with ' . $reason . ' wrong was accepted.');
        } catch (PasskeyRejected $rejected) {
            self::assertStringContainsStringIgnoringCase($reason, $rejected->getMessage());
        }
    }

    #[Test]
    public function aSignInWithoutNamingTheAccountIsRefused(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), null),
            $challenge,
            $this->rp(),
            $passkey,
        );
    }

    #[Test]
    public function aSignInNeedsTheAuthenticatorToHaveVerifiedThePerson(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner(), userVerified: false),
            $challenge,
            $this->rp(),
            $passkey,
        );
    }

    #[Test]
    public function aSecondFactorIsRefusedForAPasskeyOfAnotherAccount(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $somebodyElse = UserId::generate(new SeededRandomSource(77));
        $challenge = WebAuthnChallenge::forSecondFactor(
            new SeededRandomSource(8),
            $somebodyElse,
            'mfa-handle',
            $this->now(),
            300,
        );

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), $this->owner()),
            $challenge,
            $this->rp(),
            $passkey,
        );
    }

    #[Test]
    public function aSecondFactorNamingAnotherUserHandleIsRefused(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->secondFactor();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->authenticate($challenge, $this->rp(), UserId::generate(new SeededRandomSource(99))),
            $challenge,
            $this->rp(),
            $passkey,
        );
    }

    #[Test]
    public function anAuthenticationAnswersOnlyAChallengeMadeToSignIn(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $registration = $this->registration();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->authenticate($registration, $this->rp(), $this->owner()),
            $registration,
            $this->rp(),
            $passkey,
        );
    }

    #[Test]
    public function aRegistrationIsNotAnAuthentication(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $passkey = $this->passkeyOf($authenticator);
        $challenge = $this->signIn();

        $this->expectException(PasskeyRejected::class);

        $this->verifier()->verifyAssertion(
            $authenticator->register($challenge, $this->rp()),
            $challenge,
            $this->rp(),
            $passkey,
        );
    }

    // ── What the tests above are made of ──────────────────────────────────────────────────────

    private function rp(): RelyingParty
    {
        return RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test');
    }

    private function owner(): UserId
    {
        return UserId::generate(new SeededRandomSource(4));
    }

    private function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T10:00:00Z');
    }

    private function registration(): WebAuthnChallenge
    {
        return WebAuthnChallenge::forRegistration(new SeededRandomSource(5), $this->owner(), $this->now(), 300);
    }

    private function signIn(): WebAuthnChallenge
    {
        return WebAuthnChallenge::forSignIn(new SeededRandomSource(6), 'login-state', $this->now(), 300);
    }

    private function secondFactor(): WebAuthnChallenge
    {
        return WebAuthnChallenge::forSecondFactor(
            new SeededRandomSource(7),
            $this->owner(),
            'mfa-handle',
            $this->now(),
            300,
        );
    }

    /** The passkey a registration of this authenticator would have made, for its owner. */
    private function passkeyOf(SoftwareAuthenticator $authenticator): Passkey
    {
        $challenge = $this->registration();
        $registered = $this->verifier()->verifyRegistration(
            $authenticator->register($challenge, $this->rp()),
            $challenge,
            $this->rp(),
        );

        return self::passkeyFrom($registered, $this->owner());
    }

    private static function passkeyFrom(VerifiedRegistration $registered, UserId $owner): Passkey
    {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(11)),
            $owner,
            $registered->credentialId,
            $registered->publicKey,
            $registered->algorithm,
            $registered->signCount,
            $registered->transports,
            $registered->aaguid,
            $registered->backupEligible,
            $registered->backedUp,
            PasskeyName::fromString('Test key'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
