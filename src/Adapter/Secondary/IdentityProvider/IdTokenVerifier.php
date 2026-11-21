<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Clock;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use JsonException;
use Throwable;

/**
 * Checks an ID token an upstream OpenID provider issued for one of this server's sign-ins
 * (OpenID Connect Core §3.1.3.7): the signature against the provider's published keys,
 * then the issuer, the audience, the expiry and the `nonce` this sign-in sent.
 *
 * The signature is what makes the claims the provider's rather than the network's or the
 * browser's. Only asymmetric algorithms are accepted — RS256, PS256, ES256 — so `none`,
 * and HS256 with a public key as the secret, find nothing to verify with.
 *
 * The keys are cached for an hour by `jwks_uri`. A token signed with a key the cached set
 * does not hold triggers one fresh fetch, so a rotation at the provider costs one fetch,
 * not an outage.
 */
final readonly class IdTokenVerifier
{
    /** How long a provider's keys are trusted without fetching them again. */
    public const int JWKS_LIFETIME_SECONDS = 3600;

    /** Seconds of clock difference with the provider tolerated on `exp`. */
    private const int LEEWAY_SECONDS = 60;

    public function __construct(
        private ProviderHttp $http,
        private JwksCache $cache,
        private Clock $clock,
    ) {
    }

    /**
     * @return array<string, mixed> The verified claims.
     *
     * @throws IdentityProviderFailed
     */
    public function verify(string $provider, string $idToken, OidcSettings $settings, Nonce $nonce): array
    {
        try {
            $jws = new CompactSerializer()->unserialize($idToken);
        } catch (Throwable) {
            $this->http->fail($provider, 'the ID token is not a compact JWS.');
        }
        if ($jws->countSignatures() !== 1) {
            $this->http->fail($provider, 'the ID token does not carry exactly one signature.');
        }
        /** @var mixed $kid */
        $kid = $jws->getSignature(0)->getProtectedHeader()['kid'] ?? null;
        $kid = is_string($kid) ? $kid : null;

        $jwksUri = $settings->jwksUri->value;
        $cached = $this->cache->get($jwksUri);
        $keys = $cached === null ? null : $this->keySet($provider, $cached, $kid);
        $verified = $keys !== null && $this->verifies($jws, $keys);
        if (! $verified) {
            // Not cached, or the provider rotated since: fetch once more.
            $document = json_encode($this->http->get($provider, $jwksUri), JSON_THROW_ON_ERROR);
            $this->cache->put($jwksUri, $document, self::JWKS_LIFETIME_SECONDS);
            $keys = $this->keySet($provider, $document, $kid);
            if ($keys === null || ! $this->verifies($jws, $keys)) {
                $this->http->fail($provider, 'the ID token signature does not verify against the published keys.');
            }
        }

        return $this->checkedClaims($provider, $jws, $settings, $nonce);
    }

    /**
     * The keys of the document the token may have been signed with: the one its `kid`
     * names, or all of them when it names none. Null when there is none.
     */
    private function keySet(string $provider, string $document, ?string $kid): ?JWKSet
    {
        try {
            $set = JWKSet::createFromJson($document);
        } catch (Throwable) {
            $this->http->fail($provider, 'the JWKS is not a JSON Web Key Set.');
        }

        $keys = array_values(array_filter(
            $set->all(),
            static fn (JWK $key): bool => $kid === null || ($key->has('kid') && $key->get('kid') === $kid),
        ));

        return $keys === [] ? null : new JWKSet($keys);
    }

    private function verifies(JWS $jws, JWKSet $keys): bool
    {
        try {
            return new JWSVerifier(new AlgorithmManager([new RS256(), new PS256(), new ES256()]))
                ->verifyWithKeySet($jws, $keys, 0);
        } catch (Throwable) {
            // An algorithm outside the three, or a header the library cannot read.
            return false;
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws IdentityProviderFailed
     */
    private function checkedClaims(string $provider, JWS $jws, OidcSettings $settings, Nonce $nonce): array
    {
        try {
            /** @var mixed $claims */
            $claims = json_decode((string) $jws->getPayload(), true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $this->http->fail($provider, 'the ID token payload is not JSON.');
        }
        if (! is_array($claims) || ($claims !== [] && array_is_list($claims))) {
            $this->http->fail($provider, 'the ID token payload is not a JSON object.');
        }
        /** @var array<string, mixed> $claims */

        if (($claims['iss'] ?? null) !== $settings->issuer->value) {
            $this->http->fail($provider, 'the ID token was issued by somebody else.');
        }

        /** @var mixed $audience */
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? $audience : []);
        if (! in_array($settings->clientId, $audiences, true)) {
            $this->http->fail($provider, 'the ID token is for another audience.');
        }
        // OIDC Core §3.1.3.7 (4, 5): with several audiences, the token names who it was for.
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $settings->clientId) {
            $this->http->fail($provider, 'the ID token is for several audiences and not authorized for this one.');
        }

        /** @var mixed $expiry */
        $expiry = $claims['exp'] ?? null;
        if (! is_int($expiry) || $expiry + self::LEEWAY_SECONDS <= $this->clock->now()->getTimestamp()) {
            $this->http->fail($provider, 'the ID token has expired.');
        }

        // The nonce ties the token to this sign-in: one minted for another never carries it.
        /** @var mixed $echoed */
        $echoed = $claims['nonce'] ?? null;
        if (! is_string($echoed) || ! hash_equals($nonce->value, $echoed)) {
            $this->http->fail($provider, 'the ID token does not carry this sign-in\'s nonce.');
        }

        return $claims;
    }
}
