<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * That a client registered itself (RFC 7591), and what lets it manage that registration: the
 * digest of its registration access token (RFC 7592 §1). An operator's client has none, so the
 * configuration endpoint can never reach it (docs/design/dynamic-client-registration.md §2).
 */
final readonly class ClientRegistration
{
    /**
     * @param InitialAccessTokenId|null $initialAccessTokenId The token it registered with; null once
     *                                                        that token no longer exists.
     * @param DateTimeImmutable|null    $firstUsedAt          When it was first issued a token; null
     *                                                        until then.
     */
    public function __construct(
        public ClientId $clientId,
        public Digest $accessTokenDigest,
        public ?InitialAccessTokenId $initialAccessTokenId,
        public DateTimeImmutable $registeredAt,
        public ?DateTimeImmutable $firstUsedAt = null,
    ) {
    }

    /**
     * The same registration, answered from now on by another registration access token: each
     * update hands out a new one (RFC 7592 §3), so one that leaked stops working at the next.
     */
    public function rotate(Digest $accessTokenDigest): self
    {
        return clone($this, ['accessTokenDigest' => $accessTokenDigest]);
    }
}
