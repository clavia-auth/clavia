<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * The claims of an ID token (OIDC Core §2): who authenticated, to whom it is said, when
 * and how — then whatever the granted scope releases about the person.
 *
 * Built once, at the token endpoint, from what the authorization code carried; the
 * signing is somebody else's job.
 */
final readonly class IdTokenClaims
{
    /**
     * @param array<non-empty-string, string|bool|int|list<string>> $claims
     */
    private function __construct(private array $claims)
    {
    }

    /**
     * @param non-empty-string $issuer          The issuer identifier, exactly as discovery states it.
     * @param positive-int     $lifetimeSeconds
     * @param string           $atHash          The half hash of the access token issued alongside
     *                                          (OIDC Core §3.1.3.6), which binds the two together.
     */
    public static function issue(
        string $issuer,
        User $user,
        ClientId $audience,
        ScopeSet $scope,
        ?Nonce $nonce,
        AuthenticationContext $authentication,
        string $atHash,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        $issuedAt = $now->getTimestamp();

        $claims = [
            'iss' => $issuer,
            // The stable, opaque account id — never the email address: OIDC Core §2
            // forbids reassigning a `sub`, and addresses change hands.
            'sub' => $user->id->value,
            // One audience, so a string (OIDC Core §2 allows it) and no `azp`.
            'aud' => $audience->value,
            'exp' => $issuedAt + $lifetimeSeconds,
            'iat' => $issuedAt,
        ];

        // Only an authentication this server witnessed is reported. Saying "now" for an
        // unknown time would be a lie a relying party enforcing `max_age` relies on.
        if ($authentication->authenticatedAt !== null) {
            $claims['auth_time'] = $authentication->authenticatedAt->getTimestamp();
        }
        if ($nonce !== null) {
            // Verbatim: the relying party compares it with the value it stored.
            $claims['nonce'] = $nonce->value;
        }
        if ($authentication->methods !== []) {
            $claims['amr'] = $authentication->methodValues();
        }
        if ($authentication->sid !== null) {
            // The session a later logout token names (Back-Channel Logout 1.0 §2.1).
            $claims['sid'] = $authentication->sid;
        }
        $claims['at_hash'] = $atHash;

        // The protocol claims above win over identity claims of the same name (`sub`).
        return new self($claims + IdentityClaims::of($user, $scope));
    }

    /**
     * @return array<non-empty-string, string|bool|int|list<string>>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
