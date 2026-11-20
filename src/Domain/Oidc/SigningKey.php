<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A key this server signs tokens with, described by its public half and its place in
 * the rotation.
 *
 * The private half is not here, and never is: only the signing backend holds it. This
 * object answers the questions everything else asks — which key signs, which keys a
 * relying party must still be able to verify with — and enforces the one rule of the
 * lifecycle: a key that stops signing stays published until every token it could have
 * signed has expired.
 */
final class SigningKey
{
    private function __construct(
        public readonly PublicJwk $publicJwk,
        private SigningKeyStatus $status,
        public readonly DateTimeImmutable $createdAt,
        private ?DateTimeImmutable $retiredAt,
        private ?DateTimeImmutable $publishedUntil,
    ) {
    }

    /** A key that has just been created and signs from now on. */
    public static function activate(PublicJwk $publicJwk, DateTimeImmutable $now): self
    {
        return new self($publicJwk, SigningKeyStatus::Active, $now, null, null);
    }

    /**
     * Rebuild a key from storage.
     *
     * @throws InvalidValue When the dates contradict the status: an active key has neither, a
     *                      retired one has both.
     */
    public static function reconstitute(
        PublicJwk $publicJwk,
        SigningKeyStatus $status,
        DateTimeImmutable $createdAt,
        ?DateTimeImmutable $retiredAt,
        ?DateTimeImmutable $publishedUntil,
    ): self {
        $retired = $status === SigningKeyStatus::Retired;
        if ($retired !== ($retiredAt !== null) || $retired !== ($publishedUntil !== null)) {
            throw new InvalidValue('A retired signing key has a retirement date and a publication end; '
                . 'an active one has neither.');
        }

        return new self($publicJwk, $status, $createdAt, $retiredAt, $publishedUntil);
    }

    /** @return non-empty-string */
    public function kid(): string
    {
        return $this->publicJwk->kid;
    }

    public function algorithm(): SigningAlgorithm
    {
        return $this->publicJwk->algorithm;
    }

    public function status(): SigningKeyStatus
    {
        return $this->status;
    }

    public function isActive(): bool
    {
        return $this->status === SigningKeyStatus::Active;
    }

    public function retiredAt(): ?DateTimeImmutable
    {
        return $this->retiredAt;
    }

    /** When the key leaves the JWKS; null while it is active. */
    public function publishedUntil(): ?DateTimeImmutable
    {
        return $this->publishedUntil;
    }

    /**
     * Stop signing with this key, and keep publishing it for `$graceSeconds`.
     *
     * The grace must outlast every token the key could have signed in its last moments
     * as the active key, plus however long a relying party may cache the JWKS; withdraw
     * it sooner and tokens still within their lifetime stop verifying.
     *
     * Retiring a retired key changes nothing: its publication window was fixed when it
     * stopped signing, and is not reopened.
     *
     * @param positive-int $graceSeconds
     */
    public function retire(DateTimeImmutable $now, int $graceSeconds): void
    {
        if (! $this->isActive()) {
            return;
        }

        $this->status = SigningKeyStatus::Retired;
        $this->retiredAt = $now;
        $this->publishedUntil = $now->modify(sprintf('+%d seconds', $graceSeconds));
    }

    /**
     * Whether a relying party must still find this key in the JWKS: while it signs, and
     * until its publication window closes.
     */
    public function isPublishedAt(DateTimeImmutable $now): bool
    {
        return $this->publishedUntil === null || $now < $this->publishedUntil;
    }
}
