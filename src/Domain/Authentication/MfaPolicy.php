<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Shared\InvalidValue;

/**
 * Whether an application, or an API, takes people in on one factor
 * (docs/design/mfa-policies.md §2). Required on either one is required for a request.
 *
 * - **optional** (the default): what the request asks with `acr_values`, and nothing more.
 *   A person's own second factor is asked whatever the policy.
 * - **required**: the MFA level ({@see AuthenticationLevel::Mfa}). A stronger level is asked
 *   with `acr_values`.
 *
 * A policy applies to new authorizations: tokens issued before it keep working, and report
 * the `acr` they were issued with.
 */
enum MfaPolicy: string
{
    case Optional = 'optional';
    case Required = 'required';

    /**
     * @throws InvalidValue When the value names no policy.
     */
    public static function fromString(string $value): self
    {
        return self::tryFrom($value) ?? throw new InvalidValue("An MFA policy is 'optional' or 'required'.");
    }

    /** The level this policy demands; null for none. */
    public function level(): ?AuthenticationLevel
    {
        return $this === self::Required ? AuthenticationLevel::Mfa : null;
    }
}
