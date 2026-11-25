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
use DateTimeImmutable;
use LogicException;

/**
 * The claims of an ID token (OIDC Core §2): who authenticated, to whom it is said, when
 * and how — and nothing else about the person.
 *
 * What a scope releases (`profile`, `email`) comes from userinfo, which is where OIDC
 * Core §5.4 puts it whenever an access token is issued — always, here. An ID token
 * travels further than a userinfo response: through the browser, back as
 * `id_token_hint`, into logs. `sub` is all a relying party needs from it to know who
 * signed in.
 *
 * Built once, at the token endpoint, from what the authorization code carried; the
 * signing is somebody else's job.
 */
final readonly class IdTokenClaims
{
    /**
     * The `typ` header an ID token carries (RFC 7515 §4.1.9). OIDC Core names none; `JWT`
     * keeps it apart from a logout token (`logout+jwt`) and an access token (`at+jwt`), which
     * the same keys sign (RFC 8725 §3.11).
     */
    public const string TYPE = 'JWT';

    /**
     * @param array<non-empty-string, mixed> $claims
     */
    private function __construct(private array $claims)
    {
    }

    /**
     * @param non-empty-string $issuer          The issuer identifier, exactly as discovery states it.
     * @param positive-int     $lifetimeSeconds
     * @param string           $atHash          The half hash of the access token issued alongside
     *                                          (OIDC Core §3.1.3.6), which binds the two together.
     * @param array<non-empty-string, mixed> $custom The application's custom claims for its ID
     *                                               tokens (docs/design/custom-claims.md), added after
     *                                               the protocol's, which they never replace.
     *
     * @throws LogicException When a custom claim would replace a protocol claim.
     */
    public static function issue(
        string $issuer,
        User $user,
        ClientId $audience,
        ?Nonce $nonce,
        AuthenticationContext $authentication,
        string $atHash,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        array $custom = [],
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
        $acr = $authentication->acr();
        if ($acr !== null) {
            // The level those methods meet (OIDC Core §2); one factor has none, and says so
            // by leaving the claim out.
            $claims['acr'] = $acr;
        }
        if ($authentication->sid !== null) {
            // The session a later logout token names (Back-Channel Logout 1.0 §2.1).
            $claims['sid'] = $authentication->sid;
        }
        $claims['at_hash'] = $atHash;
        /** @var mixed $value */
        foreach ($custom as $name => $value) {
            if (array_key_exists($name, $claims)) {
                throw new LogicException('A custom claim would replace a protocol claim of the ID token.');
            }
            /** @psalm-suppress MixedAssignment */
            $claims[$name] = $value;
        }

        return new self($claims);
    }

    /**
     * @return array<non-empty-string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
