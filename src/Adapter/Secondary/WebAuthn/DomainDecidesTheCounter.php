<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\WebAuthn;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * A signature counter the library does not judge.
 *
 * Whether a counter grew is a rule of the passkey, and its refusal is an event worth auditing:
 * `Passkey::recordUse()` decides, and throws `CounterRegressed`. The library's own checker would
 * refuse the response here, as one more verification failure, and the reason would be lost.
 */
final class DomainDecidesTheCounter implements CounterChecker
{
    #[\Override]
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void
    {
    }
}
