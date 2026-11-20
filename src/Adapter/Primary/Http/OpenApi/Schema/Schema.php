<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

/**
 * A compiled OpenAPI 3.0 Schema Object: every keyword the validator enforces, checked
 * and typed by {@see SchemaCompiler}. Annotations (`description`, `example`, `default`,
 * `title`, `deprecated`, `xml`, `externalDocs`, `discriminator`) are accepted by the
 * compiler and not kept: they do not constrain an instance.
 *
 * A reference is a schema with only {@see self::$reference} set; {@see self::target()}
 * follows it.
 */
final readonly class Schema
{
    /**
     * @param list<mixed>|null              $enum       JSON values (objects as `stdClass`).
     * @param non-negative-int|null         $minLength  In Unicode code points.
     * @param non-negative-int|null         $maxLength
     * @param non-empty-string|null         $pattern    A PCRE pattern, delimiters included.
     * @param string|null                   $source     The pattern as written, for messages.
     * @param non-negative-int|null         $minItems
     * @param non-negative-int|null         $maxItems
     * @param array<string, Schema>         $properties
     * @param list<string>                  $required
     * @param non-negative-int|null         $minProperties
     * @param non-negative-int|null         $maxProperties
     * @param list<Schema>                  $allOf
     * @param list<Schema>                  $anyOf
     * @param list<Schema>                  $oneOf
     */
    public function __construct(
        public ?Type $type = null,
        public bool $nullable = false,
        public ?string $format = null,
        public ?array $enum = null,
        public ?int $minLength = null,
        public ?int $maxLength = null,
        public ?string $pattern = null,
        public ?string $source = null,
        public int|float|null $minimum = null,
        public bool $exclusiveMinimum = false,
        public int|float|null $maximum = null,
        public bool $exclusiveMaximum = false,
        public int|float|null $multipleOf = null,
        public ?Schema $items = null,
        public ?int $minItems = null,
        public ?int $maxItems = null,
        public bool $uniqueItems = false,
        public array $properties = [],
        public array $required = [],
        public Schema|bool $additionalProperties = true,
        public ?int $minProperties = null,
        public ?int $maxProperties = null,
        public array $allOf = [],
        public array $anyOf = [],
        public array $oneOf = [],
        public ?Schema $not = null,
        public bool $readOnly = false,
        public bool $writeOnly = false,
        public ?SchemaSlot $reference = null,
    ) {
    }

    public static function referenceTo(SchemaSlot $slot): self
    {
        return new self(reference: $slot);
    }

    /** The schema itself, or the one it refers to — through any number of references. */
    public function target(): self
    {
        $schema = $this;
        while ($schema->reference !== null) {
            $schema = $schema->reference->schema();
        }

        return $schema;
    }
}
