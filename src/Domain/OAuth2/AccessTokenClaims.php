<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use LogicException;

/**
 * The claims of a JWT access token, in the profile of RFC 9068 §2.2: whom it is for,
 * who it stands for, on behalf of which client, until when, and what it allows.
 *
 * Built from the token this server records, so the JWT and the row it is looked up by say
 * the same thing. Every claim §2.2 requires is present:
 *
 * - `iss`, `exp`, `iat`, `jti` (the recorded token's id, unique per token);
 * - `aud`: the API, the one value a resource server must find before reading the scope
 *   (§4) — a token naming no API is never a JWT;
 * - `sub`: the person, or — for a token a client obtained as itself — the client's id
 *   (§2.2). The two cannot collide (§5): an account id is a hyphenated UUID, and a client
 *   id this server generates is letters and digits only;
 * - `client_id`: the client it was issued to (RFC 8693 §4.3).
 *
 * `scope` (§2.2.3) is the granted scope, left out when nothing was granted. The
 * authentication claims of §2.2.1 (`auth_time`, `acr`, `amr`) are left out: §2.2.1 wants
 * them identical on every token descended from one authorization, and a refreshed token
 * no longer knows how its person signed in. Identity claims (§2.2.2) are left out too:
 * an access token travels to every API it names, and userinfo is where a person's
 * details are released.
 */
final readonly class AccessTokenClaims
{
    /** The `typ` header of a JWT access token (RFC 9068 §2.1). */
    public const string TYPE = 'at+jwt';

    /**
     * @param array<non-empty-string, string|int> $claims
     */
    private function __construct(private array $claims)
    {
    }

    /**
     * @param non-empty-string $issuer The issuer identifier, exactly as discovery states it.
     *
     * @throws LogicException When the token names no API: such a token is never a JWT.
     */
    public static function of(string $issuer, AccessToken $token): self
    {
        if ($token->audience === null) {
            throw new LogicException('A JWT access token names its API (RFC 9068 §2.2): this one names none.');
        }

        $claims = [
            'iss' => $issuer,
            'exp' => $token->expiresAt->getTimestamp(),
            // One audience, so a string (RFC 7519 §4.1.3 allows it).
            'aud' => $token->audience->value,
            'sub' => $token->userId->value ?? $token->clientId->value,
            'client_id' => $token->clientId->value,
            'iat' => $token->issuedAt->getTimestamp(),
            'jti' => $token->id->value,
        ];
        if (! $token->scope->isEmpty()) {
            $claims['scope'] = $token->scope->toString();
        }

        return new self($claims);
    }

    /**
     * @return array<non-empty-string, string|int>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
