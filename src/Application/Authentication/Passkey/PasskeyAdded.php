<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\PasskeyName;

/**
 * A passkey was registered on the account.
 */
final readonly class PasskeyAdded
{
    /**
     * @param list<string>|null $recoveryCodes Issued when this passkey is the account's first second
     *                                         factor and it held no recovery codes: the only time they
     *                                         exist in the clear. Null otherwise.
     */
    public function __construct(
        public PasskeyName $name,
        public ?array $recoveryCodes,
    ) {
    }
}
