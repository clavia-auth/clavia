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
 * How strong a sign-in was, as an Authentication Context Class Reference: the `acr` an ID
 * token, a JWT access token and introspection report (OIDC Core §2, RFC 9470 §6), and the
 * values discovery lists (`acr_values_supported`). Design: `docs/design/mfa-policies.md` §3.
 *
 * A ladder of three, each meeting every one below it:
 *
 * - **MFA**: more than one factor (`amr` holds `mfa`). Spelled as the OpenID Provider
 *   Authentication Policy Extension 1.0's multi-factor policy, the value relying parties
 *   written for the hosted providers already send.
 * - **phishing-resistant** (`phr`, OpenID Connect EAP ACR Values 1.0): MFA with a passkey
 *   (`hwk` or `swk`). A password typed before it could have been phished; the passkey's
 *   signature, bound to this origin, cannot be relayed.
 * - **phishing-resistant, hardware** (`phrh`): MFA with a device-bound passkey (`hwk`).
 *
 * One factor is no level at all, and has no `acr`: OIDC Core §2 makes the claim optional,
 * and its `"0"` describes something weaker than a password.
 *
 * Worked out from the methods a sign-in recorded, never stored: `amr` is the record of what
 * happened, and a level kept beside it could disagree with it.
 */
enum AuthenticationLevel: string
{
    case Mfa = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';
    case PhishingResistant = 'phr';
    case PhishingResistantHardware = 'phrh';

    /**
     * The strongest level these methods meet; null for one factor, or none at all.
     *
     * @param list<AuthenticationMethod> $methods
     */
    public static function of(array $methods): ?self
    {
        if (! in_array(AuthenticationMethod::MultipleFactors, $methods, true)) {
            return null;
        }
        if (in_array(AuthenticationMethod::HardwareKey, $methods, true)) {
            return self::PhishingResistantHardware;
        }
        if (in_array(AuthenticationMethod::SoftwareKey, $methods, true)) {
            return self::PhishingResistant;
        }

        return self::Mfa;
    }

    /** Whether a sign-in at this level is enough for one asking for `$required`. */
    public function meets(self $required): bool
    {
        return $this->rank() >= $required->rank();
    }

    /** The `acr` value. */
    public function acr(): string
    {
        return $this->value;
    }

    /**
     * Every level, weakest first: `acr_values_supported`.
     *
     * @return list<string>
     */
    public static function supportedAcrValues(): array
    {
        return array_map(static fn (self $level): string => $level->value, self::cases());
    }

    private function rank(): int
    {
        return match ($this) {
            self::Mfa => 1,
            self::PhishingResistant => 2,
            self::PhishingResistantHardware => 3,
        };
    }
}
