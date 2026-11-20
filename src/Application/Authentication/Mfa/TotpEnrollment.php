<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

/**
 * A seed being enrolled, as the set-up page shows it: the base32 key to type, and the
 * `otpauth://` URI its QR code encodes. Shown to the account holder only.
 */
final readonly class TotpEnrollment
{
    public function __construct(
        #[\SensitiveParameter] public string $secret,
        #[\SensitiveParameter] public string $provisioningUri,
    ) {
    }
}
