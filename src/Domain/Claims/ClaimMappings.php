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

/**
 * The custom claims of an API (or, later, of an application): at most {@see MAX} mappings, names
 * unique, and no two reading the same or nested metadata, so what they add is bounded by the
 * metadata's own size (docs/design/custom-claims.md §2, "Sizes").
 */
final readonly class ClaimMappings
{
    public const int MAX = 20;

    /** @param list<ClaimMapping> $mappings */
    private function __construct(public array $mappings)
    {
    }

    public static function none(): self
    {
        return new self([]);
    }

    /**
     * @param list<ClaimMapping> $mappings
     *
     * @throws InvalidValue
     */
    public static function of(array $mappings): self
    {
        if (count($mappings) > self::MAX) {
            throw new InvalidValue(sprintf('At most %d custom claims.', self::MAX));
        }
        foreach ($mappings as $i => $mapping) {
            foreach (array_slice($mappings, $i + 1) as $other) {
                if ($mapping->name->value === $other->name->value) {
                    throw new InvalidValue('Two custom claims have the same name.');
                }
                if ($mapping->source->overlaps($other->source)) {
                    throw new InvalidValue('Two custom claims read the same metadata, or one reads inside the other.');
                }
            }
        }

        return new self($mappings);
    }

    /**
     * An API's mappings as storage holds them (JSON of {@see ClaimMapping::toArray()}), names
     * read without the reserved check ({@see ClaimName::fromStorage()}).
     *
     * @throws InvalidValue When the stored JSON is not mappings.
     */
    public static function forApiFromJson(string $json): self
    {
        return self::fromJson($json, forApplication: false);
    }

    /**
     * An application's mappings as storage holds them, each with the places it goes (`in`).
     *
     * @throws InvalidValue When the stored JSON is not mappings.
     */
    public static function forApplicationFromJson(string $json): self
    {
        return self::fromJson($json, forApplication: true);
    }

    /** @throws InvalidValue */
    private static function fromJson(string $json, bool $forApplication): self
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, false, 32, JSON_THROW_ON_ERROR);
        if (! is_array($decoded)) {
            throw new InvalidValue('Stored custom claims are a list.');
        }
        $mappings = [];
        /** @var mixed $item */
        foreach ($decoded as $item) {
            /** @var mixed $name */
            $name = $item instanceof \stdClass ? ($item->name ?? null) : null;
            /** @var mixed $source */
            $source = $item instanceof \stdClass ? ($item->source ?? null) : null;
            if (! $item instanceof \stdClass || ! is_string($name) || ! is_string($source)) {
                throw new InvalidValue('A stored custom claim is an object with a name and a source.');
            }
            $value = property_exists($item, 'value')
                ? json_encode($item->value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)
                : null;
            $claimName = ClaimName::fromStorage($name);
            $claimSource = ClaimSource::fromString($source, $value);
            if (! $forApplication) {
                $mappings[] = ClaimMapping::forApi($claimName, $claimSource);
                continue;
            }
            /** @var mixed $in */
            $in = $item->in ?? null;
            $mappings[] = ClaimMapping::forApplication($claimName, $claimSource, self::destinations($in));
        }

        return self::of($mappings);
    }

    /**
     * @return list<ClaimDestination>
     *
     * @throws InvalidValue
     */
    public static function destinations(mixed $in): array
    {
        if (! is_array($in)) {
            throw new InvalidValue("'in' is a list of 'id_token' and 'userinfo'.");
        }
        $destinations = [];
        /** @var mixed $value */
        foreach ($in as $value) {
            $destination = is_string($value) ? ClaimDestination::tryFrom($value) : null;
            $destinations[] = $destination ?? throw new InvalidValue("'in' is a list of 'id_token' and 'userinfo'.");
        }

        return $destinations;
    }

    /** As storage holds it: a JSON list. */
    public function toJson(): string
    {
        return json_encode(
            array_map(static fn (ClaimMapping $mapping): array => $mapping->toArray(), $this->mappings),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR,
        );
    }

    public function isEmpty(): bool
    {
        return $this->mappings === [];
    }

    /** Whether any mapping reads something only a person has. */
    public function readAPerson(): bool
    {
        foreach ($this->mappings as $mapping) {
            if ($mapping->source->kind->readsAPerson()) {
                return true;
            }
        }

        return false;
    }
}
