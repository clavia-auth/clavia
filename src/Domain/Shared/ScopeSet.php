<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use Countable;
use IteratorAggregate;
use Traversable;

/**
 * A set of scopes: what a request asks for, what a token carries.
 *
 * RFC 6749 §3.3 makes the wire form a space-delimited list in which order does not
 * matter and repetition means nothing, so this is a set: duplicates collapse and two
 * sets with the same members are equal. The order of first appearance is kept only so
 * that what is sent back reads like what was sent in.
 *
 * Narrowing is the operation that matters — a token is issued for the intersection of
 * what was asked, what the API declares and what the subject holds, and nothing ever
 * widens a set after the fact.
 *
 * @implements IteratorAggregate<int, Scope>
 */
final readonly class ScopeSet implements Countable, IteratorAggregate
{
    /**
     * @param array<array-key, Scope> $scopes Keyed by their value.
     */
    private function __construct(private array $scopes)
    {
        // The keys exist for set arithmetic only. PHP turns an all-digit key into an
        // integer, so values are always read back from the Scope objects, never the keys.
    }

    public static function empty(): self
    {
        return new self([]);
    }

    public static function of(Scope ...$scopes): self
    {
        $unique = [];
        foreach ($scopes as $scope) {
            $unique[$scope->value] ??= $scope;
        }

        return new self($unique);
    }

    /**
     * Parse the `scope` parameter of a request or the stored form of a grant.
     *
     * Tokens are separated by single spaces (RFC 6749 §3.3). Leading, trailing and
     * repeated spaces are tolerated — clients send them — but any other separator is a
     * malformed scope, not a list to guess at.
     *
     * @throws InvalidValue When a token holds a forbidden character.
     */
    public static function fromString(string $scope): self
    {
        $tokens = array_values(array_filter(explode(' ', $scope), static fn (string $token): bool => $token !== ''));

        return self::of(...array_map(Scope::fromString(...), $tokens));
    }

    public function isEmpty(): bool
    {
        return $this->scopes === [];
    }

    public function contains(Scope|string $scope): bool
    {
        return isset($this->scopes[$scope instanceof Scope ? $scope->value : $scope]);
    }

    /** Whether every scope here is also in `$other`: asking for this is not asking for more. */
    public function isSubsetOf(self $other): bool
    {
        return array_diff_key($this->scopes, $other->scopes) === [];
    }

    /** The scopes present in both: this set, narrowed to what `$other` allows. */
    public function intersect(self $other): self
    {
        return new self(array_intersect_key($this->scopes, $other->scopes));
    }

    /** The scopes here that are not in `$other`. */
    public function without(self $other): self
    {
        return new self(array_diff_key($this->scopes, $other->scopes));
    }

    /** Every scope of both sets. */
    public function union(self $other): self
    {
        return new self($this->scopes + $other->scopes);
    }

    public function equals(self $other): bool
    {
        return count($this->scopes) === count($other->scopes) && $this->isSubsetOf($other);
    }

    /**
     * @return list<non-empty-string>
     */
    public function toList(): array
    {
        return array_values(array_map(static fn (Scope $scope): string => $scope->value, $this->scopes));
    }

    /** The space-delimited wire form (RFC 6749 §3.3). */
    public function toString(): string
    {
        return implode(' ', $this->toList());
    }

    #[\Override]
    public function count(): int
    {
        return count($this->scopes);
    }

    /**
     * @return Traversable<int, Scope>
     */
    #[\Override]
    public function getIterator(): Traversable
    {
        yield from array_values($this->scopes);
    }
}
