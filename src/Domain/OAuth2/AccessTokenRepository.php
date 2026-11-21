<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * Where issued access tokens are kept.
 */
interface AccessTokenRepository
{
    public function add(AccessToken $token): void;

    public function findByDigest(Digest $digest): ?AccessToken;

    /**
     * Revoke one token, unless it is revoked already: the first instant stands.
     *
     * @return int 1 when it was revoked now, 0 otherwise.
     */
    public function revoke(AccessTokenId $id, DateTimeImmutable $now): int;

    /**
     * Revoke every token minted from one authorization code that is not revoked already.
     *
     * What a replayed code obliges the server to do (RFC 6749 §4.1.2): a code seen twice
     * has leaked, and there is no telling which of the two callers was legitimate.
     *
     * @return int How many tokens were revoked.
     */
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int;

    /**
     * Revoke every token that came with or from one refresh token family: revoking the
     * family and leaving its access tokens running would leave a detected leak open for
     * an access token's lifetime.
     *
     * @return int How many tokens were revoked.
     */
    public function revokeFamily(RefreshTokenId $family, DateTimeImmutable $now): int;
}
