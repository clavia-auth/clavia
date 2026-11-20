<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\UserId;

/**
 * Sealing and unsealing TOTP seeds, and the URI that hands one to an app.
 *
 * A seed is sealed with its account in the associated data (`user:<id>:totp`), so a
 * ciphertext copied onto another account's row does not open there.
 */
final readonly class TotpSeeds
{
    /**
     * @param string $issuer What the authenticator app shows above the code: `Clavia (example.com)`.
     */
    public function __construct(
        private SecretCipher $cipher,
        private string $issuer,
    ) {
    }

    public function seal(UserId $userId, TotpSecret $secret): string
    {
        return $this->cipher->encrypt($secret->base32(), self::context($userId));
    }

    public function open(MfaFactor $factor): TotpSecret
    {
        return TotpSecret::fromBase32($this->cipher->decrypt($factor->sealedSecret, self::context($factor->userId)));
    }

    public function enrollment(TotpSecret $secret, string $account): TotpEnrollment
    {
        return new TotpEnrollment($secret->base32(), Totp::provisioningUri($secret, $account, $this->issuer));
    }

    private static function context(UserId $userId): string
    {
        return 'user:' . $userId->value . ':totp';
    }
}
