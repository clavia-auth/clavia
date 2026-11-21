<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

/**
 * How a sign-in was authenticated, as an Authentication Method Reference (RFC 8176 §2).
 *
 * Recorded on the session when it is established and never recomputed: it describes an
 * event. The values are the registered ones relying parties look for in the `amr` claim.
 */
enum AuthenticationMethod: string
{
    /** A password was typed on the login page. */
    case Password = 'pwd';

    /**
     * An external identity provider authenticated the person (Google, GitHub). Not a
     * value of the RFC 8176 registry, which names how a person proved who they are and
     * has none for "another provider vouched for them" — how they proved it there is the
     * provider's to say. OpenID Connect Core §2 leaves `amr` values to agreement between
     * the parties.
     */
    case External = 'ext';

    /**
     * A one-time password was entered: a TOTP code from an authenticator app, or a code or
     * single-use link sent by email — a secret delivered out of band, which is the closest
     * the RFC 8176 registry comes to "proved control of a mailbox".
     */
    case OneTimePassword = 'otp';

    /**
     * More than one factor was used (RFC 8176 §2: "multiple-factor authentication"). Added
     * whenever a second factor completes the sign-in — a TOTP code or a recovery code —
     * so a relying party that only looks for `mfa` finds it either way.
     */
    case MultipleFactors = 'mfa';

    /**
     * The first factor followed by a second: each method once, in order, then `mfa`.
     *
     * @param list<self> $firstFactor
     * @param list<self> $secondFactor
     *
     * @return list<self>
     */
    public static function combined(array $firstFactor, array $secondFactor): array
    {
        $methods = [];
        foreach ([...$firstFactor, ...$secondFactor, self::MultipleFactors] as $method) {
            if (! in_array($method, $methods, true)) {
                $methods[] = $method;
            }
        }

        return $methods;
    }
}
