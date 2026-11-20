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
use Clavia\Domain\Identity\User;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\Oidc\IdTokenClaims;
use DateTimeImmutable;

/**
 * Mints the ID token of an authorization code exchange (OIDC Core §3.1.3.3).
 *
 * Everything it reports comes from the code — the audience, the nonce, when and how the
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
    ) {
    }

    /**
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
        $key = $this->signer->activeKey();

        $claims = IdTokenClaims::issue(
            $this->issuer,
            $user,
            $code->clientId,
            $code->scope,
            $code->nonce,
            $code->authentication,
            // Hashed with the hash of the algorithm that signs the token (OIDC Core §3.1.3.6).
            $key->algorithm->halfHash($accessToken),
            $now,
            $this->lifetimeSeconds,
        );

        return $this->jws->sign($key, $claims->toArray());
    }
}
