<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The public half of a signing key, as a JSON Web Key (RFC 7517), ready to publish in
 * the JWKS.
 *
 * It holds the public members and nothing else, by construction: there is no field a
 * private component could be put in, and {@see fromArray()} refuses a document that
 * carries one. That is what lets the JWKS be rendered from stored values with no code
 * path on which `d`, `p` or `q` could reach the response.
 *
 * The `kid` is the key's RFC 7638 thumbprint: derived from the key itself, so it is
 * stable, unique in practice, and says nothing about where the key lives.
 */
final readonly class PublicJwk
{
    /** Members that exist only in a private RSA key (RFC 7518 §6.3.2). */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

    /**
     * @param non-empty-string $kid
     * @param non-empty-string $modulus  `n`, base64url.
     * @param non-empty-string $exponent `e`, base64url.
     */
    private function __construct(
        public string $kid,
        public SigningAlgorithm $algorithm,
        private string $modulus,
        private string $exponent,
    ) {
    }

    /**
     * Describe an RSA public key from its modulus and public exponent.
     *
     * @param string $modulus  Unsigned big-endian bytes.
     * @param string $exponent Unsigned big-endian bytes.
     *
     * @throws InvalidValue When either number is empty or zero.
     */
    public static function rsa(string $modulus, string $exponent, SigningAlgorithm $algorithm): self
    {
        // RFC 7518 §6.3.1.1: the octets "MUST NOT be zero-padded".
        $modulus = ltrim($modulus, "\0");
        $exponent = ltrim($exponent, "\0");
        if ($modulus === '' || $exponent === '') {
            throw new InvalidValue('An RSA public key has a non-zero modulus and exponent.');
        }

        $n = Base64Url::encode($modulus);
        $e = Base64Url::encode($exponent);
        assert($n !== '' && $e !== '');

        return new self(self::thumbprint($n, $e), $algorithm, $n, $e);
    }

    /**
     * Read back a key published earlier.
     *
     * @param array<array-key, mixed> $jwk
     *
     * @throws InvalidValue When the document is not an RSA signing key for a supported algorithm,
     *                      carries a private member, or its `kid` is not its thumbprint.
     */
    public static function fromArray(array $jwk): self
    {
        foreach (self::PRIVATE_MEMBERS as $member) {
            if (array_key_exists($member, $jwk)) {
                throw new InvalidValue(sprintf("A public JWK must not carry the private member '%s'.", $member));
            }
        }

        $algorithm = isset($jwk['alg']) && is_string($jwk['alg']) ? SigningAlgorithm::tryFrom($jwk['alg']) : null;
        if ($algorithm === null || ($jwk['kty'] ?? null) !== $algorithm->keyType() || ($jwk['use'] ?? null) !== 'sig') {
            throw new InvalidValue('A public JWK here is an RSA signing key for a supported algorithm.');
        }

        $n = $jwk['n'] ?? null;
        $e = $jwk['e'] ?? null;
        if (! is_string($n) || ! is_string($e)) {
            throw new InvalidValue("An RSA public JWK has string 'n' and 'e' members.");
        }

        $key = self::rsa(Base64Url::decode($n), Base64Url::decode($e), $algorithm);
        if (($jwk['kid'] ?? null) !== $key->kid) {
            throw new InvalidValue("A public JWK's 'kid' is its RFC 7638 thumbprint.");
        }

        return $key;
    }

    /**
     * The JWK as published (RFC 7517 §4, RFC 7518 §6.3.1).
     *
     * @return array{kty: string, use: 'sig', alg: string, kid: non-empty-string, n: non-empty-string,
     *               e: non-empty-string}
     */
    public function toArray(): array
    {
        return [
            'kty' => $this->algorithm->keyType(),
            'use' => 'sig',
            'alg' => $this->algorithm->value,
            'kid' => $this->kid,
            'n' => $this->modulus,
            'e' => $this->exponent,
        ];
    }

    /**
     * RFC 7638 §3: SHA-256 over the required members, in lexicographic order, with no
     * whitespace — for RSA, `{"e":…,"kty":"RSA","n":…}`.
     *
     * @return non-empty-string
     */
    private static function thumbprint(string $n, string $e): string
    {
        $canonical = sprintf('{"e":"%s","kty":"RSA","n":"%s"}', $e, $n);
        $thumbprint = Base64Url::encode(hash('sha256', $canonical, true));
        assert($thumbprint !== '');

        return $thumbprint;
    }
}
