<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Identity\UserId;
use Closure;
use LogicException;

/**
 * A WebAuthn authenticator in software: it holds a real key (EdDSA, ES256 or RS256) and builds
 * the responses a browser would send, in the shape of `PublicKeyCredential.toJSON()` — real
 * CBOR, real authenticator data, real signatures (WebAuthn Level 3 §6, §7).
 *
 * That is what lets the verifier be tested against genuine responses rather than against
 * fixtures that only the verifier's own author has ever read. Each ceremony takes named
 * arguments that break one thing — the origin, the relying party id, the challenge, a flag, the
 * signature, the user handle — so a refusal can be shown to be the response's fault and nothing
 * else. Nothing here is a verifier: it signs whatever it is told to.
 */
final class SoftwareAuthenticator
{
    private const int UP = 0x01;

    private const int UV = 0x04;

    private const int BE = 0x08;

    private const int BS = 0x10;

    private const int AT = 0x40;

    /**
     * @param Closure(string): string $signer Signs a message with the authenticator's key.
     */
    private function __construct(
        public readonly CoseAlgorithm $algorithm,
        public readonly string $credentialId,
        public readonly string $coseKey,
        private readonly Closure $signer,
        public readonly bool $synced,
        public readonly ?Aaguid $aaguid,
    ) {
    }

    /**
     * A new authenticator with a fresh key. `$synced` is whether a credential manager backs its
     * passkeys up (the backup eligibility and state flags).
     */
    public static function generate(
        CoseAlgorithm $algorithm,
        bool $synced = false,
        ?string $credentialId = null,
        ?Aaguid $aaguid = null,
    ): self {
        $credentialId ??= random_bytes(32);

        return match ($algorithm) {
            CoseAlgorithm::EdDSA => self::ed25519($credentialId, $synced, $aaguid),
            CoseAlgorithm::ES256 => self::es256($credentialId, $synced, $aaguid),
            CoseAlgorithm::RS256 => self::rs256($credentialId, $synced, $aaguid),
        };
    }

    /**
     * The response to `navigator.credentials.create()`, as `toJSON()` writes it.
     *
     * @param list<string> $transports
     */
    public function register(
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
        ?string $origin = null,
        ?string $rpId = null,
        string $type = 'webauthn.create',
        ?string $challengeBytes = null,
        bool $userPresent = true,
        bool $userVerified = true,
        ?bool $backupEligible = null,
        ?bool $backedUp = null,
        int $signCount = 0,
        array $transports = ['internal', 'hybrid'],
        ?int $coseAlgorithm = null,
        ?string $attestationFormat = null,
    ): string {
        $coseKey = $coseAlgorithm === null ? $this->coseKey : self::replaceAlgorithm($this->coseKey, $coseAlgorithm);
        $authenticatorData = $this->authenticatorData(
            $rpId ?? $relyingParty->id,
            $userPresent,
            $userVerified,
            $backupEligible ?? $this->synced,
            $backedUp ?? $this->synced,
            $signCount,
            attested: $this->aaguidBytes()
                . pack('n', strlen($this->credentialId)) . $this->credentialId . $coseKey,
        );
        $attestationObject = (string) MapObject::create([
            MapItem::create(TextStringObject::create('fmt'), TextStringObject::create($attestationFormat ?? 'none')),
            MapItem::create(TextStringObject::create('attStmt'), MapObject::create()),
            MapItem::create(TextStringObject::create('authData'), ByteStringObject::create($authenticatorData)),
        ]);

        return self::json([
            'id' => self::b64($this->credentialId),
            'rawId' => self::b64($this->credentialId),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'clientExtensionResults' => new \stdClass(),
            'response' => [
                'clientDataJSON' => self::b64(
                    self::clientData($type, $challengeBytes ?? $challenge->challenge, $origin ?? $relyingParty->origin),
                ),
                'attestationObject' => self::b64($attestationObject),
                'transports' => $transports,
                'authenticatorData' => self::b64($authenticatorData),
                'publicKey' => self::b64($coseKey),
                'publicKeyAlgorithm' => $this->algorithm->value,
            ],
        ]);
    }

    /**
     * The response to `navigator.credentials.get()`, as `toJSON()` writes it.
     *
     * @param ?UserId $userHandle         What the response names as the account (null: the field is left out).
     * @param bool    $signWithAnotherKey Whether a different key of the same kind makes the signature.
     * @param bool    $flipSignature      Whether one bit of the signature is wrong.
     * @param bool    $tamperAfterSigning Whether the authenticator data is changed once signed.
     */
    public function authenticate(
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
        ?UserId $userHandle,
        int $signCount = 1,
        ?string $origin = null,
        ?string $rpId = null,
        string $type = 'webauthn.get',
        ?string $challengeBytes = null,
        bool $userPresent = true,
        bool $userVerified = true,
        ?bool $backupEligible = null,
        ?bool $backedUp = null,
        bool $signWithAnotherKey = false,
        bool $flipSignature = false,
        bool $tamperAfterSigning = false,
        ?string $credentialId = null,
    ): string {
        $authenticatorData = $this->authenticatorData(
            $rpId ?? $relyingParty->id,
            $userPresent,
            $userVerified,
            $backupEligible ?? $this->synced,
            $backedUp ?? $this->synced,
            $signCount,
        );
        $clientData = self::clientData(
            $type,
            $challengeBytes ?? $challenge->challenge,
            $origin ?? $relyingParty->origin,
        );
        $signer = $signWithAnotherKey ? self::generate($this->algorithm) : $this;
        $signature = $signer->sign($authenticatorData . hash('sha256', $clientData, true));
        if ($flipSignature) {
            $signature[strlen($signature) - 1] = chr(ord($signature[strlen($signature) - 1]) ^ 0x01);
        }
        if ($tamperAfterSigning) {
            $authenticatorData[32] = chr(ord($authenticatorData[32]) ^ self::UV);
        }
        $id = self::b64($credentialId ?? $this->credentialId);
        $response = [
            'clientDataJSON' => self::b64($clientData),
            'authenticatorData' => self::b64($authenticatorData),
            'signature' => self::b64($signature),
        ];
        if ($userHandle !== null) {
            $response['userHandle'] = self::b64($userHandle->toBytes());
        }

        return self::json([
            'id' => $id,
            'rawId' => $id,
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'clientExtensionResults' => new \stdClass(),
            'response' => $response,
        ]);
    }

    private function sign(string $message): string
    {
        return ($this->signer)($message);
    }

    private static function ed25519(string $credentialId, bool $synced, ?Aaguid $aaguid): self
    {
        $pair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($pair);

        return new self(
            CoseAlgorithm::EdDSA,
            $credentialId,
            // An OKP key (RFC 9053 §7.2): curve Ed25519 (6), and the public key in x.
            self::coseKey(1, CoseAlgorithm::EdDSA, [-1 => 6, -2 => sodium_crypto_sign_publickey($pair)]),
            static fn (string $message): string => sodium_crypto_sign_detached($message, $secret),
            $synced,
            $aaguid,
        );
    }

    private static function es256(string $credentialId, bool $synced, ?Aaguid $aaguid): self
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($key === false || $details === false) {
            throw new LogicException('OpenSSL cannot make a P-256 key.');
        }
        /** @var array{x: string, y: string} $ec */
        $ec = $details['ec'];

        return new self(
            CoseAlgorithm::ES256,
            $credentialId,
            // An EC2 key (RFC 9053 §7.1.1): curve P-256 (1), and the point in x and y.
            self::coseKey(2, CoseAlgorithm::ES256, [
                -1 => 1,
                -2 => str_pad($ec['x'], 32, "\x00", STR_PAD_LEFT),
                -3 => str_pad($ec['y'], 32, "\x00", STR_PAD_LEFT),
            ]),
            static function (string $message) use ($key): string {
                openssl_sign($message, $signature, $key, OPENSSL_ALGO_SHA256);

                return $signature;
            },
            $synced,
            $aaguid,
        );
    }

    private static function rs256(string $credentialId, bool $synced, ?Aaguid $aaguid): self
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($key === false || $details === false) {
            throw new LogicException('OpenSSL cannot make an RSA key.');
        }
        /** @var array{n: string, e: string} $rsa */
        $rsa = $details['rsa'];

        return new self(
            CoseAlgorithm::RS256,
            $credentialId,
            // An RSA key (RFC 8230 §4): the modulus in n and the exponent in e.
            self::coseKey(3, CoseAlgorithm::RS256, [-1 => $rsa['n'], -2 => $rsa['e']]),
            static function (string $message) use ($key): string {
                openssl_sign($message, $signature, $key, OPENSSL_ALGO_SHA256);

                return $signature;
            },
            $synced,
            $aaguid,
        );
    }

    /**
     * A COSE_Key (RFC 9052 §7): the key type (1), the algorithm (3), then the key\'s own
     * parameters, whose label is negative and whose value is an integer or a byte string.
     *
     * @param array<int, int|string> $parameters
     */
    private static function coseKey(int $keyType, CoseAlgorithm $algorithm, array $parameters): string
    {
        $items = [
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($keyType)),
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create($algorithm->value)),
        ];
        foreach ($parameters as $label => $value) {
            $items[] = MapItem::create(
                NegativeIntegerObject::create($label),
                is_int($value) ? UnsignedIntegerObject::create($value) : ByteStringObject::create($value),
            );
        }

        return (string) MapObject::create($items);
    }

    /** The make of this authenticator as authenticator data holds it: sixteen bytes, zeros if it has none. */
    private function aaguidBytes(): string
    {
        return $this->aaguid === null
            ? str_repeat("\x00", 16)
            : (string) hex2bin(str_replace('-', '', $this->aaguid->value));
    }

    /** WebAuthn Level 3 §6.1: rpIdHash, flags, counter, and — at registration — the credential. */
    private function authenticatorData(
        string $rpId,
        bool $userPresent,
        bool $userVerified,
        bool $backupEligible,
        bool $backedUp,
        int $signCount,
        ?string $attested = null,
    ): string {
        $flags = ($userPresent ? self::UP : 0)
            | ($userVerified ? self::UV : 0)
            | ($backupEligible ? self::BE : 0)
            | ($backedUp ? self::BS : 0)
            | ($attested === null ? 0 : self::AT);

        return hash('sha256', $rpId, true) . chr($flags) . pack('N', $signCount) . ($attested ?? '');
    }

    /** WebAuthn Level 3 §5.8.1: the JSON the browser signs over. */
    private static function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => self::b64($challenge),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private static function replaceAlgorithm(string $coseKey, int $algorithm): string
    {
        $current = self::algorithmParameter(self::currentAlgorithmOf($coseKey));
        $position = strpos($coseKey, $current);
        if ($position === false) {
            throw new LogicException('The COSE key has no algorithm to replace.');
        }

        return substr_replace($coseKey, self::algorithmParameter($algorithm), $position, strlen($current));
    }

    /** The COSE key parameter `alg` (3) with its value, as CBOR. */
    private static function algorithmParameter(int $algorithm): string
    {
        return (string) UnsignedIntegerObject::create(3) . (string) NegativeIntegerObject::create($algorithm);
    }

    private static function currentAlgorithmOf(string $coseKey): int
    {
        foreach (CoseAlgorithm::cases() as $candidate) {
            if (str_contains($coseKey, self::algorithmParameter($candidate->value))) {
                return $candidate->value;
            }
        }

        throw new LogicException('The COSE key names an algorithm this authenticator does not know.');
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** @param array<string, mixed> $data */
    private static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
