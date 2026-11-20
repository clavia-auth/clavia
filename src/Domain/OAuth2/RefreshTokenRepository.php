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
 * Where refresh tokens are kept. A spent token is kept too: presented again, it has to be
 * recognised as a replay.
 */
interface RefreshTokenRepository
{
    public function add(RefreshToken $token): void;

    public function findByDigest(Digest $digest): ?RefreshToken;

    /**
     * The token with this digest, locked until the surrounding transaction ends, so two
     * refreshes with one token cannot both spend it. Only inside a transaction.
     */
    public function lockForRefresh(Digest $digest): ?RefreshToken;

    /** Record that the token was spent. */
    public function save(RefreshToken $token): void;

    /**
     * Revoke every token of one family that is not revoked already.
     *
     * @return int How many tokens were revoked.
     */
    public function revokeFamily(RefreshTokenId $family, DateTimeImmutable $now): int;

    /**
     * Revoke every token descended from one authorization code: what a replayed code
     * obliges the server to do once that code has bought a session.
     *
     * @return int How many tokens were revoked.
     */
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int;
}
