<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;
use LogicException;

/**
 * A second factor enrolled on an account: a TOTP authenticator.
 *
 * Two states. **Pending** — the person has been shown a seed but has not proven their app
 * produces the right codes; it enforces nothing, so scanning a QR code and walking away
 * locks nobody out. **Confirmed** — sign-in demands a code. Confirmation needs one
 * correct code ({@see self::confirm()}), and a confirmed factor is never re-staged:
 * replacing it goes through turning it off first, a deliberate act.
 *
 * One factor of each type per account, keyed `(user, type)`. The seed is held sealed —
 * this object never sees it in the clear except for the duration of {@see self::accept()}
 * — and the last time step accepted is remembered, so no code works twice.
 */
final class MfaFactor
{
    private function __construct(
        public readonly UserId $userId,
        public readonly MfaFactorType $type,
        /** The seed as {@see \Clavia\Application\Port\SecretCipher} sealed it, bound to this account. */
        public private(set) string $sealedSecret,
        public private(set) ?DateTimeImmutable $confirmedAt,
        public private(set) ?int $lastUsedStep,
        public readonly DateTimeImmutable $createdAt,
    ) {
    }

    /** A pending TOTP factor holding a freshly sealed seed. */
    public static function stage(UserId $userId, string $sealedSecret, DateTimeImmutable $now): self
    {
        return new self($userId, MfaFactorType::Totp, $sealedSecret, null, null, $now);
    }

    public static function reconstitute(
        UserId $userId,
        MfaFactorType $type,
        string $sealedSecret,
        ?DateTimeImmutable $confirmedAt,
        ?int $lastUsedStep,
        DateTimeImmutable $createdAt,
    ): self {
        return new self($userId, $type, $sealedSecret, $confirmedAt, $lastUsedStep, $createdAt);
    }

    public function isConfirmed(): bool
    {
        return $this->confirmedAt !== null;
    }

    /**
     * Replace a pending factor's seed — a new enrollment attempt — forgetting any step the
     * old seed spent.
     *
     * @throws FactorAlreadyConfirmed
     */
    public function restage(string $sealedSecret): void
    {
        if ($this->isConfirmed()) {
            throw new FactorAlreadyConfirmed();
        }
        $this->sealedSecret = $sealedSecret;
        $this->lastUsedStep = null;
    }

    /**
     * Whether `$code` is a code of `$secret` at `$now` that has not been used: when it is,
     * its time step is spent here, so the same code — or any older one — is refused next
     * time. Persisting the spent step is the caller's, under the row lock it read this
     * factor with.
     *
     * @param TotpSecret $secret This factor's seed, unsealed for the check.
     */
    #[\NoDiscard]
    public function accept(TotpSecret $secret, #[\SensitiveParameter] string $code, DateTimeImmutable $now): bool
    {
        $step = Totp::match($secret, self::normalise($code), $now, $this->lastUsedStep);
        if ($step === null) {
            return false;
        }
        $this->lastUsedStep = $step;

        return true;
    }

    /**
     * Turn the factor on. Only after {@see self::accept()} has said yes to a code: that is
     * the proof the person's app holds the same seed.
     *
     * @throws LogicException When no code has been accepted yet, or the factor is already on.
     */
    public function confirm(DateTimeImmutable $now): void
    {
        if ($this->isConfirmed()) {
            throw new LogicException('This factor is already confirmed.');
        }
        if ($this->lastUsedStep === null) {
            throw new LogicException('A factor is confirmed only once a code from it has been accepted.');
        }
        $this->confirmedAt = $now;
    }

    /** Spaces people type between groups of digits do not count. */
    private static function normalise(string $code): string
    {
        return str_replace([' ', "\t"], '', trim($code));
    }
}
