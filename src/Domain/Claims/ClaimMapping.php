<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use Clavia\Domain\Shared\InvalidValue;

/** One custom claim: its name, what it reads, and where it goes. */
final readonly class ClaimMapping
{
    /** @param non-empty-list<ClaimDestination> $destinations */
    private function __construct(
        public ClaimName $name,
        public ClaimSource $source,
        public array $destinations,
    ) {
    }

    /**
     * A mapping of an API: for its access tokens. `roles` is allowed as a name, from the roles
     * source only (RFC 9068 §2.2.3.1).
     *
     * @throws InvalidValue
     */
    public static function forApi(ClaimName $name, ClaimSource $source): self
    {
        if ($name->value === ClaimName::ROLES && $source->kind !== ClaimSourceKind::Roles) {
            throw new InvalidValue("The 'roles' claim is read from the 'roles' source.");
        }

        return new self($name, $source, [ClaimDestination::AccessToken]);
    }

    /**
     * A mapping of an application: for its ID tokens, its userinfo answers, or both. Never `roles`
     * as a name, which RFC 9068 defines for access tokens only ({@see ClaimName::fromString()}).
     *
     * @param list<ClaimDestination> $destinations
     *
     * @throws InvalidValue When it goes nowhere, twice somewhere, or to an access token.
     */
    public static function forApplication(ClaimName $name, ClaimSource $source, array $destinations): self
    {
        if ($destinations === []) {
            throw new InvalidValue("An application's custom claim goes to the ID token, userinfo, or both.");
        }
        if (in_array(ClaimDestination::AccessToken, $destinations, true)) {
            throw new InvalidValue(
                "An application's custom claims go to its ID tokens and userinfo; an API's to its access tokens.",
            );
        }
        $names = array_map(static fn (ClaimDestination $d): string => $d->value, $destinations);
        if (count(array_unique($names)) !== count($destinations)) {
            throw new InvalidValue('A custom claim names each destination once.');
        }
        if ($name->value === ClaimName::ROLES) {
            throw new InvalidValue("The 'roles' claim is an access token's (RFC 9068 §2.2.3.1).");
        }
        // In a fixed order, so the same mapping reads back the same.
        usort($destinations, static fn (ClaimDestination $a, ClaimDestination $b): int => strcmp($a->value, $b->value));

        return new self($name, $source, $destinations);
    }

    /**
     * As storage and the Management API write it: `{name, source}`, `value` for a constant, and
     * `in` for an application's (where it goes).
     *
     * @return array{name: string, source: string, value?: mixed, in?: list<string>}
     */
    public function toArray(): array
    {
        $mapping = ['name' => $this->name->value, 'source' => $this->source->toString()];
        if ($this->source->constant !== null) {
            /** @psalm-suppress MixedAssignment Any JSON. */
            $mapping['value'] = json_decode($this->source->constant, false, 16, JSON_THROW_ON_ERROR);
        }
        if ($this->destinations !== [ClaimDestination::AccessToken]) {
            $mapping['in'] = array_map(static fn (ClaimDestination $d): string => $d->value, $this->destinations);
        }

        return $mapping;
    }

    public function goesTo(ClaimDestination $destination): bool
    {
        return in_array($destination, $this->destinations, true);
    }
}
