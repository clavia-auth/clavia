<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;

/**
 * Which second factors can answer a challenge: the ones the account holds, and — for a
 * step-up — only those that make the sign-in meet what the request asks for
 * ({@see MfaChallenge::isAnsweredBy()}). One answer for the page that offers them, the
 * step-up that must not open a challenge nobody can answer, and the answers themselves.
 */
final readonly class SecondFactors
{
    /** What an authenticator app's code adds to `amr`. */
    public const array APP = [AuthenticationMethod::OneTimePassword];

    /** What a recovery code adds: `mfa` alone, which {@see AuthenticationMethod::combined()} always adds. */
    public const array RECOVERY_CODE = [];

    /** What any passkey adds, for the level it reaches: a key, synced or not, is `phr` alike. */
    public const array PASSKEY = [AuthenticationMethod::SoftwareKey];

    /**
     * @param PasskeyRepository|null $passkeys Null when passkeys are off.
     */
    public function __construct(
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
        private ?PasskeyRepository $passkeys,
    ) {
    }

    public function offeredFor(MfaChallenge $challenge): OfferedSecondFactors
    {
        $userId = $challenge->userId;
        $app = ($this->factors->find($userId)?->isConfirmed() ?? false)
            && $challenge->isAnsweredBy(self::APP);
        // A recovery code answers a sign-in whatever the factor; a step-up only if it is enough.
        $recoveryCode = $challenge->isStepUp()
            ? $this->recoveryCodes->unusedCount($userId) > 0 && $challenge->isAnsweredBy(self::RECOVERY_CODE)
            : true;
        // A passkey after a passkey is one device counted twice.
        $passkey = ! $challenge->firstFactorWasAPasskey()
            && ($this->passkeys?->countOf($userId) ?? 0) > 0
            && $challenge->isAnsweredBy(self::PASSKEY);

        return new OfferedSecondFactors($app, $recoveryCode, $passkey);
    }
}
