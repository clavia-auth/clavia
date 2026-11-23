<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * A DPoP client for tests (RFC 9449 §4): a real key pair, and proofs signed with it, as a client
 * library would make them — or broken on purpose, for the refusals.
 */
final class DpopClient
{
    private int $sequence = 0;

    private function __construct(public readonly JWK $key, public readonly string $algorithm)
    {
    }

    public static function es256(): self
    {
        return new self(JWKFactory::createECKey('P-256'), 'ES256');
    }

    public static function edDsa(): self
    {
        return new self(JWKFactory::createOKPKey('Ed25519'), 'EdDSA');
    }

    public static function rs256(int $bits = 2048): self
    {
        return new self(self::rsaKey($bits), 'RS256');
    }

    /** RSA keys are slow to make: one per size, for the whole run. */
    private static function rsaKey(int $bits): JWK
    {
        /** @var array<int, JWK> $keys */
        static $keys = [];

        return $keys[$bits] ??= JWKFactory::createRSAKey($bits);
    }

    /** The RFC 7638 thumbprint of the public key: what `cnf.jkt` must say. */
    public function thumbprint(): string
    {
        return $this->key->toPublic()->thumbprint('sha256');
    }

    /**
     * A proof for one request.
     *
     * @param array<string, mixed> $claims  Laid over the claims a proof carries; null removes one.
     * @param array<string, mixed> $headers Laid over the protected header.
     */
    public function proof(
        string $method,
        string $url,
        ?string $nonce = null,
        ?string $accessToken = null,
        array $claims = [],
        array $headers = [],
        ?int $issuedAt = null,
    ): string {
        $payload = array_filter([
            'jti' => 'proof-' . ++$this->sequence . '-' . bin2hex(random_bytes(6)),
            'htm' => $method,
            'htu' => $url,
            'iat' => $issuedAt ?? time(),
            'nonce' => $nonce,
            'ath' => $accessToken === null
                ? null
                : rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '='),
        ], static fn (mixed $value): bool => $value !== null);
        $payload = array_filter($claims + $payload, static fn (mixed $value): bool => $value !== null);
        $header = $headers + ['typ' => 'dpop+jwt', 'alg' => $this->algorithm, 'jwk' => $this->key->toPublic()->all()];

        $jws = new JWSBuilder(new AlgorithmManager([new ES256(), new EdDSA(), new RS256(), new HS256()]))
            ->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES))
            ->addSignature($this->key, $header)
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }
}
