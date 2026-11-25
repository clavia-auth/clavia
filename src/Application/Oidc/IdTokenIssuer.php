<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc;

use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Claims\ClaimDestination;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\Oidc\IdTokenClaims;
use Clavia\Domain\Oidc\Nonce;
use DateTimeImmutable;

/**
 * Mints the ID token issued with a person's tokens (OIDC Core §3.1.3.3).
 *
 * Everything it reports comes from the grant — the audience, the nonce, when and how the
 * person authenticated — and from the account as it is now; `at_hash` ties it to the
 * access token issued in the same response, so the two cannot be paired with others.
 */
final readonly class IdTokenIssuer
{
    /**
     * @param non-empty-string $issuer          The issuer identifier, exactly as discovery states it.
     * @param positive-int     $lifetimeSeconds
     */
    public function __construct(
        private TokenSigner $signer,
        private CompactJws $jws,
        private string $issuer,
        private int $lifetimeSeconds,
        private ApplicationClaims $claims,
    ) {
    }

    /**
     * The ID token of an authorization code exchange.
     *
     * @param string $accessToken The access token issued alongside, exactly as the client receives it.
     *
     * @throws NoActiveSigningKey
     * @throws SigningFailed
     */
    public function issue(
        AuthorizationCode $code,
        User $user,
        #[\SensitiveParameter] string $accessToken,
        DateTimeImmutable $now,
    ): string {
        return $this->issueFor(
            $code->clientId,
            $code->nonce,
            $code->authentication,
            $user,
            $accessToken,
            $now,
        );
    }

    /**
     * An ID token for any grant acting for a person — a device approved on another screen
     * has no code, and no nonce (RFC 8628 has none to carry).
     *
     * @param string $accessToken The access token issued alongside, exactly as the client receives it.
     *
     * @throws NoActiveSigningKey
     * @throws SigningFailed
     */
    public function issueFor(
        ClientId $clientId,
        ?Nonce $nonce,
        AuthenticationContext $authentication,
        User $user,
        #[\SensitiveParameter] string $accessToken,
        DateTimeImmutable $now,
    ): string {
        $key = $this->signer->activeKey();

        $claims = IdTokenClaims::issue(
            $this->issuer,
            $user,
            $clientId,
            $nonce,
            $authentication,
            // Hashed with the hash of the algorithm that signs the token (OIDC Core §3.1.3.6).
            $key->algorithm->halfHash($accessToken),
            $now,
            $this->lifetimeSeconds,
            // The application's custom claims for its ID tokens, after the protocol's.
            $this->claims->for($clientId, $user, ClaimDestination::IdToken),
        );

        return $this->jws->sign($key, $claims->toArray(), IdTokenClaims::TYPE);
    }
}
