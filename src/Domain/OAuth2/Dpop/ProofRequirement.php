<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Dpop;

use Clavia\Domain\Shared\Base64Url;
use DateTimeImmutable;
use Uri\Rfc3986\Uri;

/**
 * The request a DPoP proof must be for, and the rules of RFC 9449 §4.3 that are not cryptography
 * — the signature is the verifier's (docs/design/dpop.md §2).
 *
 * - `htm` is the request's method, exactly;
 * - `htu` is the endpoint's URL as this server knows it — never the request's `Host` — compared
 *   by scheme, host, port and path after RFC 3986 normalisation, without query or fragment
 *   (§4.3 step 9);
 * - `iat` is at most the proof lifetime old and {@see self::SKEW_SECONDS} ahead (§11.1);
 * - presented with an access token, `ath` is its hash (§4.3 step 12), and the token, when bound,
 *   is bound to this proof's key.
 *
 * The nonce and the replay of `jti` need storage, and are the application's.
 */
final readonly class ProofRequirement
{
    /** How far ahead of this server's clock a proof's `iat` may be. */
    public const int SKEW_SECONDS = 5;

    /**
     * @param non-empty-string      $method
     * @param non-empty-string      $url         The endpoint's URL as this server knows it.
     * @param non-empty-string|null $accessToken The access token the proof is presented with, if any.
     * @param JwkThumbprint|null    $boundTo     The key the presented token or code is bound to, if any.
     */
    public function __construct(
        public string $method,
        public string $url,
        public ?string $accessToken = null,
        public ?JwkThumbprint $boundTo = null,
    ) {
    }

    /**
     * @param positive-int $lifetimeSeconds How old a proof may be (`CLAVIA_DPOP_PROOF_LIFETIME`).
     *
     * @return DpopRefusal|null Null when the proof is for this request.
     */
    public function check(DpopProof $proof, DateTimeImmutable $now, int $lifetimeSeconds): ?DpopRefusal
    {
        if ($proof->method !== $this->method) {
            return DpopRefusal::WrongMethod;
        }
        if (! self::sameResource($proof->url, $this->url)) {
            return DpopRefusal::WrongUrl;
        }
        $age = $now->getTimestamp() - $proof->issuedAt->getTimestamp();
        if ($age > $lifetimeSeconds) {
            return DpopRefusal::TooOld;
        }
        if ($age < -self::SKEW_SECONDS) {
            return DpopRefusal::FromTheFuture;
        }
        $presented = $proof->accessTokenHash ?? '';
        if ($this->accessToken !== null && ! hash_equals(self::hashOf($this->accessToken), $presented)) {
            return DpopRefusal::WrongAccessToken;
        }
        if ($this->boundTo !== null && ! $this->boundTo->equals($proof->thumbprint)) {
            return DpopRefusal::WrongKey;
        }

        return null;
    }

    /**
     * `ath`: the base64url SHA-256 of an access token (RFC 9449 §4.2).
     *
     * @return non-empty-string
     */
    public static function hashOf(#[\SensitiveParameter] string $accessToken): string
    {
        $hash = Base64Url::encode(hash('sha256', $accessToken, true));
        // A SHA-256 digest is 32 bytes: never empty once encoded.
        assert($hash !== '');

        return $hash;
    }

    /** Whether two URLs name the same resource: scheme, host, port and path, normalised. */
    private static function sameResource(string $presented, string $expected): bool
    {
        $a = Uri::parse($presented);
        $b = Uri::parse($expected);
        if ($a === null || $b === null) {
            return false;
        }

        return $a->getScheme() === $b->getScheme()
            && $a->getHost() === $b->getHost()
            && self::portOf($a) === self::portOf($b)
            && ($a->getPath() === '' ? '/' : $a->getPath()) === ($b->getPath() === '' ? '/' : $b->getPath());
    }

    /** The port, the scheme's default when none is written. */
    private static function portOf(Uri $uri): ?int
    {
        return $uri->getPort() ?? match ($uri->getScheme()) {
            'https' => 443,
            'http' => 80,
            default => null,
        };
    }
}
