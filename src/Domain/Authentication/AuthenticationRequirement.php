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
 * The levels a request will accept, in the requester's order of preference: what
 * `acr_values` asks for (OIDC Core §3.1.2.1), and later what a client's or an API's MFA
 * policy demands. Design: `docs/design/mfa-policies.md` §2 and §5.1.
 *
 * A requirement, not a hint. OIDC Core calls `acr` a voluntary claim, so a server may
 * issue a weaker one; but a relying party that asks for a level because a resource server
 * refused its token (RFC 9470) needs either the level or a clear refusal, never a token
 * that fails again. A value this server does not know is ignored, so a request naming only
 * unknown values requires nothing.
 */
final readonly class AuthenticationRequirement
{
    /**
     * @param list<AuthenticationLevel> $levels
     */
    private function __construct(public array $levels)
    {
    }

    /** A request that asks for no particular level. */
    public static function none(): self
    {
        return new self([]);
    }

    /**
     * @param string|null $acrValues The parameter as received; null when absent.
     *
     * @throws InvalidValue When it is present but names nothing.
     */
    public static function fromAcrValues(?string $acrValues): self
    {
        if ($acrValues === null) {
            return self::none();
        }
        // Space-separated (OIDC Core §3.1.2.1); a value is never empty.
        $values = preg_split('/ +/', trim($acrValues), flags: PREG_SPLIT_NO_EMPTY);
        if ($values === false || $values === []) {
            throw new InvalidValue("'acr_values' names no value.");
        }

        $levels = [];
        foreach ($values as $value) {
            $level = AuthenticationLevel::tryFrom($value);
            if ($level !== null && ! in_array($level, $levels, true)) {
                $levels[] = $level;
            }
        }

        return new self($levels);
    }

    public function isEmpty(): bool
    {
        return $this->levels === [];
    }

    /**
     * Whether a sign-in with these methods is enough: it meets one of the levels accepted, or
     * nothing is required.
     *
     * @param list<AuthenticationMethod> $methods
     */
    public function isMetBy(array $methods): bool
    {
        if ($this->levels === []) {
            return true;
        }
        $reached = AuthenticationLevel::of($methods);

        return $reached !== null && array_any(
            $this->levels,
            static fn (AuthenticationLevel $level): bool => $reached->meets($level),
        );
    }

    /**
     * The `acr_values` this requirement stands for, in order.
     *
     * @return list<string>
     */
    public function acrValues(): array
    {
        return array_map(static fn (AuthenticationLevel $level): string => $level->acr(), $this->levels);
    }
}
