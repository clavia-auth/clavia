<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * The {@see TokenSigner} of every remote backend: one key that signs, and the retired keys
 * still published.
 *
 * - **The `kid` is the RFC 7638 thumbprint of the public key** the provider reports, like
 *   the `postgres` backend's: it says nothing about the account, project or vault the key
 *   lives in, and it is the same on every server reading the same key.
 * - **Retired keys** (`CLAVIA_SIGNING_RETIRED_KEY_REFS`) are published and never sign.
 *   No provider rotates an asymmetric key in place, so a rotation is a new key, with the
 *   old one kept here until every token it signed has expired.
 * - **Every signature is verified before it leaves**, against the published key. A
 *   provider that signed the wrong bytes — a digest taken for a message, a mismatched
 *   algorithm — would otherwise issue tokens that fail at every relying party and nowhere
 *   here; checking costs a fraction of the round trip that produced the signature.
 */
final class RemoteTokenSigner implements TokenSigner
{
    /** @var array<string, PublicJwk> Public halves read in this process, by reference. */
    private array $known = [];

    /**
     * @param list<RemoteSigningKey> $retired Oldest last.
     */
    public function __construct(
        private readonly RemoteSigningKey $active,
        private readonly array $retired,
        private readonly SigningAlgorithm $algorithm,
        private readonly PublicKeyCache $cache,
    ) {
    }

    #[\Override]
    public function activeKey(): SigningKeyReference
    {
        return new SigningKeyReference($this->publicKeyOf($this->active)->kid, $this->algorithm);
    }

    #[\Override]
    public function sign(SigningKeyReference $key, string $signingInput): string
    {
        $active = $this->publicKeyOf($this->active);
        if ($key->kid !== $active->kid || $key->algorithm !== $this->algorithm) {
            throw new SigningFailed(sprintf('Signing key %s is not the active key.', $key->kid));
        }

        $digest = hash($this->algorithm->hashAlgorithm(), $signingInput, true);
        $signature = $this->active->sign($digest, $this->algorithm);

        if (! self::verifier($this->algorithm)->verify(new JWK($active->toArray()), $signingInput, $signature)) {
            throw new SigningFailed(
                'The signature the signing service returned does not verify against its public key: the key, '
                . 'its algorithm or the service is not what this server expects.',
            );
        }

        return $signature;
    }

    #[\Override]
    public function publicKeys(): array
    {
        return array_map($this->publicKeyOf(...), [$this->active, ...$this->retired]);
    }

    private function publicKeyOf(RemoteSigningKey $key): PublicJwk
    {
        $reference = $key->reference();
        if (isset($this->known[$reference])) {
            return $this->known[$reference];
        }

        $publicKey = $this->cache->get($reference, $this->algorithm);
        if ($publicKey === null) {
            $publicKey = $key->publicKey($this->algorithm);
            $this->cache->put($reference, $publicKey);
        }

        return $this->known[$reference] = $publicKey;
    }

    private static function verifier(SigningAlgorithm $algorithm): SignatureAlgorithm
    {
        return match ($algorithm) {
            SigningAlgorithm::RS256 => new RS256(),
        };
    }
}
