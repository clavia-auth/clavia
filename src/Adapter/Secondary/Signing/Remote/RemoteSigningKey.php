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
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;

/**
 * One key held by a signing service that never lets it out — AWS KMS, Google Cloud KMS,
 * Azure Key Vault, an HSM — reduced to the two things this server asks of it: sign a
 * digest, and say what its public half is.
 *
 * This is also the contract of a custom backend (`CLAVIA_SIGNING_BACKEND` set to a class
 * name): implement it with a constructor taking the key reference, and the rest — the
 * `kid`, the JWKS, retired keys, caching, the check that every signature verifies — is
 * {@see RemoteTokenSigner}'s.
 *
 * **A digest, never the message.** The caller hashes the JWS signing input with the
 * algorithm's hash and hands over the result; the key signs it as RSASSA-PKCS1-v1_5
 * (adding the DigestInfo prefix itself, as every provider does). Providers disagree on
 * whether they hash — AWS by default does, GCP and Azure never do — and sending the wrong
 * shape signs the wrong bytes; one shape for all of them removes the question, and AWS's
 * 4 KB limit on a message it hashes with it.
 */
interface RemoteSigningKey
{
    /**
     * What the provider calls the key, exactly as configured. Never published: an ARN
     * carries the account, a resource name the project, a URL the vault.
     *
     * @return non-empty-string
     */
    public function reference(): string;

    /**
     * @param string $digest The hash of the signing input, raw bytes.
     *
     * @return non-empty-string The raw signature.
     *
     * @throws SigningFailed When the provider cannot be reached or refuses.
     */
    #[\NoDiscard]
    public function sign(string $digest, SigningAlgorithm $algorithm): string;

    /**
     * The public half, read from the provider — never derived from anything this
     * process holds.
     *
     * @throws SigningFailed When the provider cannot be reached, or the key is not one
     *                       that signs with `$algorithm`.
     */
    public function publicKey(SigningAlgorithm $algorithm): PublicJwk;
}
