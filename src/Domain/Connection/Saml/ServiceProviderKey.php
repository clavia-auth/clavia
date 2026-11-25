<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use LogicException;

/**
 * One of this server's keys as a SAML service provider: never its private half, which stays in its
 * backend. Named by its `kid`, the RFC 7638 thumbprint of its public key, and published as a
 * self-signed X.509 certificate (DER, base64), which is what SAML metadata carries.
 */
final readonly class ServiceProviderKey
{
    /**
     * @param non-empty-string $kid
     * @param non-empty-string $certificate DER, base64.
     */
    private function __construct(
        public string $kid,
        public ServiceProviderKeyUsage $usage,
        public ServiceProviderKeyStatus $status,
        public string $certificate,
        public DateTimeImmutable $validUntil,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $promotedAt,
        public ?DateTimeImmutable $retiredAt,
    ) {
    }

    /**
     * A new key, current at once (the first pair) or next (a rotation).
     *
     * @param non-empty-string $kid
     * @param non-empty-string $certificate
     *
     * @throws InvalidValue When it would start retired.
     */
    public static function introduce(
        string $kid,
        ServiceProviderKeyUsage $usage,
        ServiceProviderKeyStatus $status,
        string $certificate,
        DateTimeImmutable $validUntil,
        DateTimeImmutable $now,
    ): self {
        if ($status === ServiceProviderKeyStatus::Retired) {
            throw new InvalidValue('A service provider key starts as next or current.');
        }

        return new self(
            $kid,
            $usage,
            $status,
            $certificate,
            $validUntil,
            $now,
            $status === ServiceProviderKeyStatus::Current ? $now : null,
            null,
        );
    }

    /**
     * @param non-empty-string $kid
     * @param non-empty-string $certificate
     */
    public static function reconstitute(
        string $kid,
        ServiceProviderKeyUsage $usage,
        ServiceProviderKeyStatus $status,
        string $certificate,
        DateTimeImmutable $validUntil,
        DateTimeImmutable $createdAt,
        ?DateTimeImmutable $promotedAt,
        ?DateTimeImmutable $retiredAt,
    ): self {
        return new self($kid, $usage, $status, $certificate, $validUntil, $createdAt, $promotedAt, $retiredAt);
    }

    public function promoted(DateTimeImmutable $now): self
    {
        if ($this->status !== ServiceProviderKeyStatus::Next) {
            throw new LogicException('Only a next key is promoted.');
        }

        return clone($this, ['status' => ServiceProviderKeyStatus::Current, 'promotedAt' => $now]);
    }

    public function retired(DateTimeImmutable $now): self
    {
        if ($this->status !== ServiceProviderKeyStatus::Current) {
            throw new LogicException('Only a current key is retired.');
        }

        return clone($this, ['status' => ServiceProviderKeyStatus::Retired, 'retiredAt' => $now]);
    }

    /** In the metadata: the current key and the next one, never a retired one. */
    public function isPublished(): bool
    {
        return $this->status !== ServiceProviderKeyStatus::Retired;
    }

    /** Signs requests: the current signing key alone. */
    public function signs(): bool
    {
        return $this->usage === ServiceProviderKeyUsage::Signing && $this->status === ServiceProviderKeyStatus::Current;
    }

    /**
     * Decrypts content keys: an encryption key that is next (an IdP may already use it), current, or
     * retired (an IdP may not have moved yet).
     */
    public function decrypts(): bool
    {
        return $this->usage === ServiceProviderKeyUsage::Encryption;
    }

    /** SHA-256 of the certificate's DER, lower-case hex: what an IdP's administrator compares. */
    public function fingerprint(): string
    {
        return hash('sha256', (string) base64_decode($this->certificate, true));
    }
}
