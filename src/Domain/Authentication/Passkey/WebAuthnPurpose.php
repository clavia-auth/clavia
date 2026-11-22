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
 * What a WebAuthn ceremony is for. A challenge made for one purpose is refused for any other
 * (docs/design/passkeys.md §12), so a response gathered for a second factor cannot sign anyone
 * in, nor one made at sign-in register a credential.
 */
enum WebAuthnPurpose: string
{
    /** Registering a passkey on a signed-in account. */
    case Registration = 'registration';

    /** Signing in with a passkey: a first factor, the person not yet known. */
    case SignIn = 'sign_in';

    /** A passkey as the second factor of a sign-in, the account already known. */
    case SecondFactor = 'second_factor';

    /**
     * Whether the account is known before the ceremony starts. Then the passkey named by the
     * response must be that account's; otherwise the response says whose it is.
     */
    public function identifiesTheAccountFirst(): bool
    {
        return $this !== self::SignIn;
    }

    /**
     * Whether the authenticator must have verified the person (a biometric or a PIN), not only
     * have been touched: always, except for a second factor, which follows a first one.
     */
    public function requiresUserVerification(): bool
    {
        return $this !== self::SecondFactor;
    }
}
