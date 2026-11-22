<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\VerifiedAssertion;
use Clavia\Application\Port\VerifiedRegistration;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Shared\InvalidValue;
use LogicException;

/**
 * A verifier that answers what it is told, for testing the use cases around it.
 *
 * It checks nothing: that a response is genuine is the real verifier's contract
 * (`PasskeyVerifierContract`), which only real CBOR, COSE and signatures can feed, so no double
 * runs it. What the use cases need to be shown is what they do with each answer — accepted,
 * refused, with this counter, with or without user verification.
 *
 * Responses are JSON with the credential id in `id`, as a browser's `toJSON()` writes it, so a
 * test can look a passkey up by it: `{"id":"<base64url credential id>"}` is enough.
 */
final class FakePasskeyVerifier implements PasskeyVerifier
{
    private VerifiedRegistration|PasskeyRejected|null $registration = null;

    private VerifiedAssertion|PasskeyRejected|null $assertion = null;

    /** @var list<array{kind: string, response: string, challenge: WebAuthnChallenge}> What it was asked, in order. */
    public private(set) array $asked = [];

    /** Answer every registration with `$verified`. */
    public function acceptRegistrationsAs(VerifiedRegistration $verified): void
    {
        $this->registration = $verified;
    }

    /** Answer every authentication with `$verified`. */
    public function acceptAssertionsAs(VerifiedAssertion $verified): void
    {
        $this->assertion = $verified;
    }

    /** Refuse every response, whatever it is. */
    public function rejectEverything(string $reason = 'The fake verifier was told to refuse.'): void
    {
        $this->registration = PasskeyRejected::because($reason);
        $this->assertion = PasskeyRejected::because($reason);
    }

    #[\Override]
    public function credentialIdOf(string $responseJson): CredentialId
    {
        /** @var mixed $data */
        $data = json_decode($responseJson, true);
        $id = is_array($data) ? ($data['id'] ?? null) : null;
        if (! is_string($id)) {
            throw PasskeyRejected::because('The response is not a WebAuthn credential.');
        }

        try {
            return CredentialId::fromBase64Url($id);
        } catch (InvalidValue $invalid) {
            throw PasskeyRejected::because('The credential id is out of bounds.', $invalid);
        }
    }

    #[\Override]
    public function verifyRegistration(
        string $responseJson,
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
    ): VerifiedRegistration {
        $this->asked[] = ['kind' => 'registration', 'response' => $responseJson, 'challenge' => $challenge];

        return self::answer($this->registration, 'registration');
    }

    #[\Override]
    public function verifyAssertion(
        string $responseJson,
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
        Passkey $passkey,
    ): VerifiedAssertion {
        $this->asked[] = ['kind' => 'assertion', 'response' => $responseJson, 'challenge' => $challenge];

        return self::answer($this->assertion, 'authentication');
    }

    /**
     * @template T of VerifiedRegistration|VerifiedAssertion
     *
     * @param T|PasskeyRejected|null $answer
     *
     * @return T
     */
    private static function answer(
        VerifiedRegistration|VerifiedAssertion|PasskeyRejected|null $answer,
        string $what,
    ): mixed {
        return match (true) {
            $answer === null => throw new LogicException(
                'The fake verifier was not told how to answer a ' . $what . '.',
            ),
            $answer instanceof PasskeyRejected => throw $answer,
            default => $answer,
        };
    }
}
