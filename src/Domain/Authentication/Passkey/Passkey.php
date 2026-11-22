<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A passkey: a discoverable WebAuthn credential registered on an account, bound to Clavia's
 * sign-in origin (docs/design/passkeys.md).
 *
 * It is **synced** when a credential manager backs it up across devices (the backup
 * eligibility flag is set) and **device-bound** otherwise. Whether it is one or the other is
 * fixed at registration: WebAuthn Level 3 §6.1.3 forbids it to change, so nothing here can.
 *
 * What it keeps of use is a signature counter and the backup state last seen. Some
 * authenticators increment the counter on every use; synced passkeys report zero for ever.
 * A counter that fails to grow, when it is not zero throughout, may mean a cloned
 * authenticator ({@see self::recordUse()}).
 */
final class Passkey
{
    /**
     * @param list<Transport> $transports
     */
    private function __construct(
        public readonly PasskeyId $id,
        public readonly UserId $userId,
        public readonly CredentialId $credentialId,
        public readonly CosePublicKey $publicKey,
        public readonly CoseAlgorithm $algorithm,
        public private(set) int $signCount,
        public readonly array $transports,
        public readonly ?Aaguid $aaguid,
        public readonly bool $backupEligible,
        public private(set) bool $backedUp,
        public private(set) PasskeyName $name,
        public readonly DateTimeImmutable $createdAt,
        public private(set) ?DateTimeImmutable $lastUsedAt,
    ) {
    }

    /**
     * A passkey just verified at registration. The credential id must be new to Clavia: the
     * repository's unique constraint is the arbiter, not a check made first.
     *
     * @param list<Transport> $transports
     *
     * @throws InvalidValue When the counter is negative, or the credential says it is backed
     *                      up without being eligible for backup (§6.1.3: BS requires BE).
     */
    public static function register(
        PasskeyId $id,
        UserId $userId,
        CredentialId $credentialId,
        CosePublicKey $publicKey,
        CoseAlgorithm $algorithm,
        int $signCount,
        array $transports,
        ?Aaguid $aaguid,
        bool $backupEligible,
        bool $backedUp,
        PasskeyName $name,
        DateTimeImmutable $now,
    ): self {
        self::assertCounter($signCount);
        self::assertBackup($backupEligible, $backedUp);

        return new self(
            $id,
            $userId,
            $credentialId,
            $publicKey,
            $algorithm,
            $signCount,
            array_values(array_unique($transports, SORT_REGULAR)),
            $aaguid,
            $backupEligible,
            $backedUp,
            $name,
            $now,
            null,
        );
    }

    /**
     * A passkey read back from storage.
     *
     * @param list<Transport> $transports
     */
    public static function reconstitute(
        PasskeyId $id,
        UserId $userId,
        CredentialId $credentialId,
        CosePublicKey $publicKey,
        CoseAlgorithm $algorithm,
        int $signCount,
        array $transports,
        ?Aaguid $aaguid,
        bool $backupEligible,
        bool $backedUp,
        PasskeyName $name,
        DateTimeImmutable $createdAt,
        ?DateTimeImmutable $lastUsedAt,
    ): self {
        return new self(
            $id,
            $userId,
            $credentialId,
            $publicKey,
            $algorithm,
            $signCount,
            $transports,
            $aaguid,
            $backupEligible,
            $backedUp,
            $name,
            $createdAt,
            $lastUsedAt,
        );
    }

    /** Whether a credential manager backs it up across devices. */
    public function isSynced(): bool
    {
        return $this->backupEligible;
    }

    public function rename(PasskeyName $name): void
    {
        $this->name = $name;
    }

    /**
     * Record a successful use: the counter and the backup state the authenticator reported.
     *
     * The counter must have grown. The one exception is zero after zero, which is what a
     * synced passkey always reports (WebAuthn Level 3 §6.1.3): there is no counter to
     * compare. Persisting is the caller's, through the conditional write of
     * {@see PasskeyRepository::recordUse()}.
     *
     * @throws CounterRegressed When the counter did not grow and was not zero throughout.
     * @throws InvalidValue     When the counter is negative, or the authenticator says the
     *                          passkey is backed up though it was never eligible for backup.
     */
    public function recordUse(int $signCount, bool $backedUp, DateTimeImmutable $at): void
    {
        self::assertCounter($signCount);
        self::assertBackup($this->backupEligible, $backedUp);
        if (($signCount !== 0 || $this->signCount !== 0) && $signCount <= $this->signCount) {
            throw CounterRegressed::between($this->signCount, $signCount);
        }

        $this->signCount = $signCount;
        $this->backedUp = $backedUp;
        $this->lastUsedAt = $at;
    }

    /**
     * How a sign-in with this passkey is reported in `amr` (RFC 8176 §2): `hwk` for a
     * device-bound credential, `swk` for a synced one — proof of possession of a key held in
     * hardware or in software — and `user` when only the presence of somebody was tested, the
     * authenticator having verified nobody. User verification (a biometric or a PIN) adds
     * nothing to say: RFC 8176 has no value for "the authenticator verified the person" that
     * both kinds share, and `mfa` is the caller's to add.
     *
     * @return list<AuthenticationMethod>
     */
    public function authenticationMethods(bool $userVerified): array
    {
        $methods = [$this->backupEligible ? AuthenticationMethod::SoftwareKey : AuthenticationMethod::HardwareKey];
        if (! $userVerified) {
            $methods[] = AuthenticationMethod::UserPresence;
        }

        return $methods;
    }

    private static function assertCounter(int $signCount): void
    {
        if ($signCount < 0) {
            throw new InvalidValue('A signature counter is never negative.');
        }
    }

    private static function assertBackup(bool $backupEligible, bool $backedUp): void
    {
        if ($backedUp && ! $backupEligible) {
            throw new InvalidValue('A passkey cannot be backed up without being eligible for backup.');
        }
    }
}
