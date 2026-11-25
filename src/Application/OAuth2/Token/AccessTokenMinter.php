<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenClaims;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Closure;

/**
 * Mints an access token for every grant: records it, and gives back the value the client
 * receives, in the form its API takes ({@see AccessTokenFormat}).
 *
 * - **Opaque**: a random 43-character secret.
 * - **JWT**: an RFC 9068 token (`typ: at+jwt`, §2.1) signed through {@see TokenSigner} with
 *   the active key, whose claims are the recorded token's ({@see AccessTokenClaims}).
 *
 * Either way the token is recorded by the digest of that value, so introspection,
 * revocation, userinfo and the Management API find it alike. What a JWT cannot have is an
 * API that validates it on its own learning of a revocation: it accepts the token until it
 * expires.
 *
 * Signing happens before the token is recorded, so a signing failure records nothing —
 * and, inside a grant's transaction, rolls back whatever the grant had spent.
 */
final readonly class AccessTokenMinter
{
    /**
     * @param non-empty-string $issuer The issuer identifier, exactly as discovery states it.
     */
    public function __construct(
        private AccessTokenRepository $tokens,
        private ResourceServerRepository $resourceServers,
        private TokenSigner $signer,
        private CompactJws $jws,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private string $issuer,
        private ApiClaims $claims,
    ) {
    }

    /**
     * @param Closure(AccessTokenId, Digest): AccessToken $record Builds the token the grant issues,
     *                                                            under the id and digest given.
     * @param JwkThumbprint|null                         $dpopKey The DPoP key it is bound to, if any:
     *                                                            `cnf.jkt` in a JWT (RFC 9449 §6.1).
     *
     * @throws NoActiveSigningKey When the token is a JWT and there is no key to sign it.
     * @throws SigningFailed
     */
    public function mint(Closure $record, ?JwkThumbprint $dpopKey = null): MintedAccessToken
    {
        $value = $this->secrets->token();
        $token = $record(AccessTokenId::generate($this->random), Digest::of($value));
        if ($dpopKey !== null) {
            $token = $token->boundTo($dpopKey);
        }

        $api = $this->apiOf($token);
        if ($api !== null && $api->accessTokenFormat === AccessTokenFormat::Jwt) {
            // The API's custom claims, worked out now: a refresh shows what changed since.
            $value = $this->jws->sign(
                $this->signer->activeKey(),
                AccessTokenClaims::of($this->issuer, $token, $this->claims->for($api, $token))->toArray(),
                AccessTokenClaims::TYPE,
            );
            $token = $token->presentedAs(Digest::of($value));
        }

        $this->tokens->add($token);

        return new MintedAccessToken($token, $value);
    }

    /**
     * The API the token is for; none for a token naming no API, which only userinfo accepts, and
     * which is always opaque: RFC 9068 §2.2 requires an `aud`.
     */
    private function apiOf(AccessToken $token): ?ResourceServer
    {
        return $token->audience === null ? null : $this->resourceServers->findByIdentifier($token->audience);
    }
}
