<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

/**
 * How an authenticator can be reached (WebAuthn Level 3 §5.8.4), kept as a hint for the
 * browser's next request and never as a decision.
 */
enum Transport: string
{
    case Internal = 'internal';
    case Hybrid = 'hybrid';
    case Usb = 'usb';
    case Nfc = 'nfc';
    case Ble = 'ble';
}
