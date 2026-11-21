<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;
use stdClass;

/**
 * The claims of a logout token (OIDC Back-Channel Logout 1.0 §2.4): this session, this
 * person, has ended — said to one application.
 *
 * `iss`, `aud` and `iat` as in an ID token; `exp` short, because the token is consumed on
 * receipt; `sub` and `sid` both, so the application may end its sessions by either; `jti`,
 * so it can recognise a replay; the logout event in `events`. Never `nonce`: its absence
 * is what tells a logout token from an ID token (§2.6), so the one cannot be passed off as
 * the other.
 */
final readonly class LogoutTokenClaims
{
    /** The `events` member that makes a JWT a logout token (§2.4). */
    public const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /** The `typ` header a logout token carries (§2.4), as explicit typing (RFC 8725 §3.11). */
    public const string TYPE = 'logout+jwt';

    /**
     * @param array<non-empty-string, mixed> $claims
     */
    private function __construct(private array $claims)
    {
    }

    /**
     * @param non-empty-string $issuer          The issuer identifier, exactly as discovery states it.
     * @param non-empty-string $sid             The session that ended, as the client's ID tokens named it.
     * @param non-empty-string $jti             A fresh, unique identifier for this token.
     * @param positive-int     $lifetimeSeconds
     */
    public static function issue(
        string $issuer,
        ClientId $audience,
        UserId $subject,
        string $sid,
        string $jti,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        $issuedAt = $now->getTimestamp();

        return new self([
            'iss' => $issuer,
            'sub' => $subject->value,
            'aud' => $audience->value,
            'iat' => $issuedAt,
            'exp' => $issuedAt + $lifetimeSeconds,
            'jti' => $jti,
            // An empty JSON object, not an empty array: `{"…/backchannel-logout": {}}`.
            'events' => [self::EVENT => new stdClass()],
            'sid' => $sid,
        ]);
    }

    /**
     * @return array<non-empty-string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
