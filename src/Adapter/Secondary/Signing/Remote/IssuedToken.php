<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Application\Port\SigningFailed;
use DateTimeImmutable;

/**
 * A bearer token and when it expires, read from a token endpoint's answer.
 *
 * Used until {@see EARLY} seconds before it expires, so that a token is never presented in
 * the second it stops being accepted.
 */
final readonly class IssuedToken
{
    public const int EARLY = 60;

    /**
     * @param non-empty-string $token
     */
    private function __construct(
        public string $token,
        private DateTimeImmutable $expiresAt,
    ) {
    }

    /**
     * An OAuth 2.0 token response (`access_token`, `expires_in`), or the managed-identity
     * shape (`expires_on`, a Unix time — sent as a string).
     *
     * @param array<array-key, mixed> $response
     *
     * @throws SigningFailed When it carries no token or no lifetime.
     */
    public static function fromResponse(array $response, DateTimeImmutable $now, string $service): self
    {
        $token = $response['access_token'] ?? null;
        if (! is_string($token) || $token === '') {
            throw new SigningFailed(sprintf('%s issued no access token.', $service));
        }

        /** @var mixed $expiresOn */
        $expiresOn = $response['expires_on'] ?? $response['expires_at'] ?? null;
        /** @var mixed $expiresIn */
        $expiresIn = $response['expires_in'] ?? null;
        $expiresAt = match (true) {
            is_numeric($expiresOn) => $now->setTimestamp((int) $expiresOn),
            is_numeric($expiresIn) => $now->modify(sprintf('+%d seconds', (int) $expiresIn)),
            default => throw new SigningFailed(sprintf('%s did not say when its token expires.', $service)),
        };

        return new self($token, $expiresAt);
    }

    public function isUsableAt(DateTimeImmutable $now): bool
    {
        return $now < $this->expiresAt->modify(sprintf('-%d seconds', self::EARLY));
    }
}
