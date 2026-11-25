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
     * As storage and the Management API write it: `{name, source}`, and `value` for a constant.
     *
     * @return array{name: string, source: string, value?: mixed}
     */
    public function toArray(): array
    {
        $mapping = ['name' => $this->name->value, 'source' => $this->source->toString()];
        if ($this->source->constant !== null) {
            /** @psalm-suppress MixedAssignment Any JSON. */
            $mapping['value'] = json_decode($this->source->constant, false, 16, JSON_THROW_ON_ERROR);
        }

        return $mapping;
    }

    public function goesTo(ClaimDestination $destination): bool
    {
        return in_array($destination, $this->destinations, true);
    }
}
