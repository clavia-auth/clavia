<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\InvalidValue;

/**
 * Who an external provider says the person is, as it said it.
 *
 * The `subject` is the provider's own stable identifier for the account — OIDC `sub`
 * for Google, the numeric `id` for GitHub — and the only thing an identity is ever
 * matched on. The address is a claim: it means something only when the provider itself
 * reports it as verified, and never identifies anyone on its own.
 */
final readonly class AssertedIdentity
{
    /** As long as a subject can be stored; providers' identifiers are far shorter. */
    public const int MAX_SUBJECT_LENGTH = 255;

    /**
     * @param non-empty-string $subject
     */
    private function __construct(
        public ProviderName $provider,
        public string $subject,
        public ?string $email,
        public bool $emailVerified,
    ) {
    }

    /**
     * @throws InvalidValue When the subject is empty, too long or holds control characters.
     */
    public static function of(ProviderName $provider, string $subject, ?string $email, bool $emailVerified): self
    {
        $usable = $subject !== ''
            && strlen($subject) <= self::MAX_SUBJECT_LENGTH
            && preg_match('/[\x00-\x1f\x7f]/', $subject) !== 1;
        if (! $usable) {
            throw new InvalidValue('A provider subject is 1 to 255 bytes without control characters.');
        }
        $email = $email === null || trim($email) === '' ? null : trim($email);

        return new self($provider, $subject, $email, $email !== null && $emailVerified);
    }

    /** The address, when — and only when — the provider vouches for it. */
    public function verifiedEmail(): ?string
    {
        return $this->emailVerified ? $this->email : null;
    }
}
