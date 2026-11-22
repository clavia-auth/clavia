<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\VerifiedAssertion;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\FakePasskeyVerifier;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

final class FakePasskeyVerifierTest extends TestCase
{
    public function testItAnswersWhatItWasToldAndRemembersWhatItWasAsked(): void
    {
        $verifier = new FakePasskeyVerifier();
        $verified = new VerifiedAssertion(7, false, false, true);
        $verifier->acceptAssertionsAs($verified);

        self::assertSame(
            $verified,
            $verifier->verifyAssertion('{}', $this->challenge(), $this->rp(), $this->passkey()),
        );
        self::assertCount(1, $verifier->asked);
        self::assertSame('assertion', $verifier->asked[0]['kind']);
    }

    public function testItRefusesWhenToldToAndNeverGuessesWhenNot(): void
    {
        $verifier = new FakePasskeyVerifier();

        try {
            $verifier->verifyAssertion('{}', $this->challenge(), $this->rp(), $this->passkey());
            self::fail('It answered without being told how.');
        } catch (LogicException) {
            self::assertCount(1, $verifier->asked);
        }

        $verifier->rejectEverything('no');
        $this->expectException(PasskeyRejected::class);
        $verifier->verifyAssertion('{}', $this->challenge(), $this->rp(), $this->passkey());
    }

    public function testItReadsTheCredentialIdFromTheResponse(): void
    {
        $id = CredentialId::fromBytes(str_repeat("\x03", 16));

        self::assertTrue(
            new FakePasskeyVerifier()->credentialIdOf('{"id":"' . $id->toBase64Url() . '"}')->equals($id),
        );
    }

    public function testAResponseWithoutAUsableIdIsRefused(): void
    {
        $this->expectException(PasskeyRejected::class);

        new FakePasskeyVerifier()->credentialIdOf('{"id":"AAAA"}');
    }

    private function challenge(): WebAuthnChallenge
    {
        return WebAuthnChallenge::forSignIn(
            new SeededRandomSource(1),
            'login-state',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            300,
        );
    }

    private function rp(): RelyingParty
    {
        return RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test');
    }

    private function passkey(): Passkey
    {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(1)),
            UserId::generate(new SeededRandomSource(2)),
            CredentialId::fromBytes(str_repeat("\x03", 16)),
            CosePublicKey::fromBytes('k'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString('k'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
