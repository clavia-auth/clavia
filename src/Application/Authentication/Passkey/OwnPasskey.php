<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\InvalidValue;

/**
 * A passkey named by the browser, if it is the session's own. An id that is malformed, unknown
 * or someone else's is the same nothing, so the answer never says which passkeys exist.
 */
final class OwnPasskey
{
    private function __construct()
    {
    }

    public static function find(PasskeyRepository $passkeys, Session $session, string $passkeyId): ?Passkey
    {
        try {
            $passkey = $passkeys->one(PasskeyId::fromString($passkeyId));
        } catch (InvalidValue) {
            return null;
        }

        return $passkey !== null && $passkey->userId->equals($session->userId) ? $passkey : null;
    }
}
