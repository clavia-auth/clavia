<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\WebAuthn;

use CBOR\Decoder;
use CBOR\Normalizable;
use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\VerifiedAssertion;
use Clavia\Application\Port\VerifiedRegistration;
use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Shared\InvalidValue;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\Key;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\NilUuid;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\StringStream;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Verifies WebAuthn responses with `web-auth/webauthn-lib`, and is the only class that knows
 * the library, CBOR or COSE (docs/design/passkeys.md §10).
 *
 * The library does the checks of WebAuthn Level 3 §7.1 and §7.2: the type, the challenge, the
 * origin (exactly the relying party's, never a subdomain), the hash of the relying party id, user
 * presence and — where the ceremony requires it — user verification, the backup flags, the
 * extensions, the signature, and the user handle. What this adds is what the library cannot
 * know: the purpose of the ceremony (and so which of those to demand), that a response answers
 * the passkey it claims and the account the ceremony was for, and that the counter is left to the
 * passkey ({@see DomainDecidesTheCounter}).
 *
 * Every failure, the library's or this class's, is one {@see PasskeyRejected}.
 */
final readonly class WebAuthnLibPasskeyVerifier implements PasskeyVerifier
{
    /** A response is a few kilobytes; this is a bound on what is parsed, not an expectation. */
    private const int MAX_RESPONSE_BYTES = 65536;

    public function __construct(private SerializerInterface $serializer)
    {
    }

    #[\Override]
    public function credentialIdOf(string $responseJson): CredentialId
    {
        try {
            return CredentialId::fromBytes($this->credential($responseJson)->rawId);
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
        if ($challenge->purpose !== WebAuthnPurpose::Registration || $challenge->userId === null) {
            throw PasskeyRejected::because('The challenge was not made to register a passkey.');
        }
        $response = $this->credential($responseJson)->response;
        if (! $response instanceof AuthenticatorAttestationResponse) {
            throw PasskeyRejected::because('The response is not a registration.');
        }

        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($relyingParty->name, $relyingParty->id),
            PublicKeyCredentialUserEntity::create('account', $challenge->userId->toBytes(), 'account'),
            $challenge->challenge,
            array_map(
                static fn (CoseAlgorithm $algorithm): PublicKeyCredentialParameters
                    => PublicKeyCredentialParameters::createPk($algorithm->value),
                CoseAlgorithm::preferred(),
            ),
            AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );

        try {
            $record = new AuthenticatorAttestationResponseValidator(
                $this->ceremonies($relyingParty)->creationCeremony(),
            )->check($response, $options, $relyingParty->id);
            $authenticatorData = $response->attestationObject->authData;

            return new VerifiedRegistration(
                CredentialId::fromBytes($record->publicKeyCredentialId),
                CosePublicKey::fromBytes($record->credentialPublicKey),
                self::algorithmOf($record->credentialPublicKey),
                $record->counter,
                self::transports($record->transports),
                Aaguid::fromBytes($record->aaguid->toBinary()),
                $authenticatorData->isBackupEligible(),
                $authenticatorData->isBackedUp(),
                $authenticatorData->isUserVerified(),
            );
        } catch (PasskeyRejected $rejected) {
            throw $rejected;
        } catch (Throwable $failure) {
            throw PasskeyRejected::because('The registration did not verify: ' . $failure->getMessage(), $failure);
        }
    }

    #[\Override]
    public function verifyAssertion(
        string $responseJson,
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
        Passkey $passkey,
    ): VerifiedAssertion {
        if ($challenge->purpose === WebAuthnPurpose::Registration) {
            throw PasskeyRejected::because('The challenge was not made to sign in.');
        }
        $identified = $challenge->purpose->identifiesTheAccountFirst();
        if ($identified && ($challenge->userId === null || ! $challenge->userId->equals($passkey->userId))) {
            throw PasskeyRejected::because('The passkey is not the account\'s the ceremony was for.');
        }
        $credential = $this->credential($responseJson);
        $response = $credential->response;
        if (! $response instanceof AuthenticatorAssertionResponse) {
            throw PasskeyRejected::because('The response is not an authentication.');
        }
        if (! hash_equals($passkey->credentialId->bytes(), $credential->rawId)) {
            throw PasskeyRejected::because('The response is for another credential.');
        }

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge->challenge,
            $relyingParty->id,
            [],
            $challenge->purpose->requiresUserVerification()
                ? PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
                : PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        );

        try {
            new AuthenticatorAssertionResponseValidator($this->ceremonies($relyingParty)->requestCeremony())->check(
                self::recordOf($passkey),
                $response,
                $options,
                $relyingParty->id,
                // The account was known first: the response may omit the user handle, but if it
                // names one it must be this account's. Otherwise it must name the owner.
                $identified ? $passkey->userId->toBytes() : null,
            );
            $authenticatorData = $response->authenticatorData;

            return new VerifiedAssertion(
                $authenticatorData->signCount,
                $authenticatorData->isBackupEligible(),
                $authenticatorData->isBackedUp(),
                $authenticatorData->isUserVerified(),
            );
        } catch (Throwable $failure) {
            throw PasskeyRejected::because('The authentication did not verify: ' . $failure->getMessage(), $failure);
        }
    }

    private function credential(string $responseJson): PublicKeyCredential
    {
        if (strlen($responseJson) > self::MAX_RESPONSE_BYTES) {
            throw PasskeyRejected::because('The response is too large.');
        }

        try {
            $credential = $this->serializer->deserialize($responseJson, PublicKeyCredential::class, 'json');
        } catch (Throwable $unreadable) {
            throw PasskeyRejected::because('The response is not a WebAuthn credential.', $unreadable);
        }

        return $credential;
    }

    /**
     * The library's ceremonies for this relying party: its one origin, exactly; the algorithms
     * Clavia offers; and no judgement of the counter.
     */
    private function ceremonies(RelyingParty $relyingParty): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([$relyingParty->origin]);
        $factory->setAlgorithmManager(Manager::create()->add(Ed25519::create(), ES256::create(), RS256::create()));
        $factory->setCounterChecker(new DomainDecidesTheCounter());

        return $factory;
    }

    /** The passkey as the library knows a credential: what it needs to check a signature. */
    private static function recordOf(Passkey $passkey): CredentialRecord
    {
        return CredentialRecord::create(
            $passkey->credentialId->bytes(),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            array_map(static fn (Transport $transport): string => $transport->value, $passkey->transports),
            'none',
            new EmptyTrustPath(),
            $passkey->aaguid === null ? new NilUuid() : Uuid::fromString($passkey->aaguid->value),
            $passkey->publicKey->bytes(),
            $passkey->userId->toBytes(),
            $passkey->signCount,
            null,
            $passkey->backupEligible,
            $passkey->backedUp,
        );
    }

    /**
     * @param array<array-key, string> $transports
     *
     * @return list<Transport>
     */
    private static function transports(array $transports): array
    {
        $known = [];
        foreach ($transports as $transport) {
            $known[] = Transport::tryFrom($transport);
        }

        return array_values(array_unique(array_filter($known), SORT_REGULAR));
    }

    /** @throws InvalidValue When the key names an algorithm Clavia does not offer. */
    private static function algorithmOf(string $coseKey): CoseAlgorithm
    {
        $stream = new StringStream($coseKey);
        $decoded = Decoder::create()->decode($stream);
        if (! $decoded instanceof Normalizable) {
            throw new InvalidValue('The public key is not a COSE key.');
        }
        $map = $decoded->normalize();
        if (! is_array($map)) {
            throw new InvalidValue('The public key is not a COSE key.');
        }

        /** @var array<int|string, mixed> $map */
        return CoseAlgorithm::fromIdentifier(Key::create($map)->alg());
    }
}
