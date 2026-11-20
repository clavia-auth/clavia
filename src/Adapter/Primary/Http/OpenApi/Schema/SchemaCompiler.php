<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

use Clavia\Adapter\Primary\Http\OpenApi\InvalidDocument;
use Clavia\Adapter\Primary\Http\OpenApi\Node;
use Clavia\Adapter\Primary\Http\OpenApi\References;

/**
 * Turns OpenAPI 3.0 Schema Objects into {@see Schema}s, checking every keyword.
 *
 * Strict on purpose. A keyword this validator does not enforce — a misspelling
 * (`minLenght`), a JSON Schema keyword OpenAPI 3.0 does not have (`const`,
 * `patternProperties`), a 3.1 form (`type: [string, "null"]`, a numeric
 * `exclusiveMinimum`) — is refused when the document is loaded, rather than silently
 * dropping the constraint it was meant to be.
 *
 * References compile to a {@see SchemaSlot} per target, filled by {@see self::finish()},
 * so recursive schemas compile in finite time and every target is compiled once.
 */
final class SchemaCompiler
{
    private const array KEYWORDS = [
        'type', 'nullable', 'format', 'enum',
        'minLength', 'maxLength', 'pattern',
        'minimum', 'exclusiveMinimum', 'maximum', 'exclusiveMaximum', 'multipleOf',
        'items', 'minItems', 'maxItems', 'uniqueItems',
        'properties', 'required', 'additionalProperties', 'minProperties', 'maxProperties',
        'allOf', 'anyOf', 'oneOf', 'not',
        'readOnly', 'writeOnly',
        // Annotations: accepted, not enforced.
        'title', 'description', 'default', 'example', 'deprecated', 'xml', 'externalDocs', 'discriminator',
    ];

    /** @var array<string, SchemaSlot> By the pointer of their target. */
    private array $slots = [];

    /** @var list<SchemaSlot> */
    private array $pending = [];

    public function __construct(private readonly References $references)
    {
    }

    /**
     * @throws InvalidDocument
     */
    public function compile(Node $node): Schema
    {
        if (References::isReference($node)) {
            $target = $this->references->target($node);
            $slot = $this->slots[$target] ?? null;
            if ($slot === null) {
                // Resolved now, so a reference to nothing is reported where it is written.
                $this->references->at($target, $node);
                $slot = $this->slots[$target] = new SchemaSlot($target);
                $this->pending[] = $slot;
            }

            return Schema::referenceTo($slot);
        }

        return $this->compileObject($node);
    }

    /**
     * Compile every schema a reference pointed at, and the ones those point at in turn.
     *
     * @throws InvalidDocument
     */
    public function finish(): void
    {
        while (($slot = array_pop($this->pending)) !== null) {
            $target = $this->references->at($slot->pointer, Node::root(null));
            // A reference to a reference: follow the chain (refusing a loop) to the schema.
            $slot->fill($this->compileObject($this->references->resolve($target)));
        }
    }

    /**
     * @throws InvalidDocument
     */
    private function compileObject(Node $node): Schema
    {
        $node->allowOnly(self::KEYWORDS);

        $typeName = $node->stringMember('type');
        $type = $typeName === null ? null : (Type::tryFrom($typeName) ?? throw $node->member('type')->invalid(
            'must be one of ' . implode(', ', array_map(static fn (Type $type): string => $type->value, Type::cases())),
        ));
        if ($type === Type::Array && ! $node->has('items')) {
            throw $node->invalid("is an array without 'items'");
        }

        foreach (['exclusiveMinimum', 'exclusiveMaximum'] as $flag) {
            if ($node->has($flag) && ! is_bool($node->member($flag)->value)) {
                throw $node->member($flag)->invalid('must be a boolean in OpenAPI 3.0 (a number is the 3.1 form)');
            }
        }

        $readOnly = $node->boolMember('readOnly', false);
        $writeOnly = $node->boolMember('writeOnly', false);
        if ($readOnly && $writeOnly) {
            throw $node->invalid('cannot be both readOnly and writeOnly');
        }

        $minLength = $node->optional('minLength')?->count();
        $maxLength = $node->optional('maxLength')?->count();
        $minItems = $node->optional('minItems')?->count();
        $maxItems = $node->optional('maxItems')?->count();
        $minProperties = $node->optional('minProperties')?->count();
        $maxProperties = $node->optional('maxProperties')?->count();
        $minimum = $node->optional('minimum')?->number();
        $maximum = $node->optional('maximum')?->number();
        $bounds = [
            ['minLength', $minLength, $maxLength],
            ['minItems', $minItems, $maxItems],
            ['minProperties', $minProperties, $maxProperties],
            ['minimum', $minimum, $maximum],
        ];
        foreach ($bounds as [$keyword, $low, $high]) {
            if ($low !== null && $high !== null && $low > $high) {
                throw $node->member($keyword)->invalid('is greater than its maximum: no value could satisfy both');
            }
        }

        $multipleOf = $node->optional('multipleOf')?->number();
        if ($multipleOf !== null && $multipleOf <= 0) {
            throw $node->member('multipleOf')->invalid('must be greater than 0');
        }

        $source = $node->stringMember('pattern');

        return new Schema(
            type: $type,
            nullable: $node->boolMember('nullable', false),
            format: $node->stringMember('format'),
            enum: $this->enum($node),
            minLength: $minLength,
            maxLength: $maxLength,
            pattern: $source === null ? null : self::pattern($source, $node->member('pattern')),
            source: $source,
            minimum: $minimum,
            exclusiveMinimum: $node->boolMember('exclusiveMinimum', false),
            maximum: $maximum,
            exclusiveMaximum: $node->boolMember('exclusiveMaximum', false),
            multipleOf: $multipleOf,
            items: ($items = $node->optional('items')) === null ? null : $this->compile($items),
            minItems: $minItems,
            maxItems: $maxItems,
            uniqueItems: $node->boolMember('uniqueItems', false),
            properties: $this->properties($node),
            required: $this->required($node),
            additionalProperties: $this->additionalProperties($node),
            minProperties: $minProperties,
            maxProperties: $maxProperties,
            allOf: $this->subschemas($node, 'allOf'),
            anyOf: $this->subschemas($node, 'anyOf'),
            oneOf: $this->subschemas($node, 'oneOf'),
            not: ($not = $node->optional('not')) === null ? null : $this->compile($not),
            readOnly: $readOnly,
            writeOnly: $writeOnly,
        );
    }

    /**
     * @return list<mixed>|null
     *
     * @throws InvalidDocument
     */
    private function enum(Node $node): ?array
    {
        $enum = $node->optional('enum');
        if ($enum === null) {
            return null;
        }

        $values = array_map(static fn (Node $item): mixed => $item->value, $enum->items());

        return $values === [] ? throw $enum->invalid('must list at least one value') : $values;
    }

    /**
     * @return array<string, Schema>
     *
     * @throws InvalidDocument
     */
    private function properties(Node $node): array
    {
        $properties = [];
        foreach ($node->optional('properties')?->members() ?? [] as $property) {
            $properties[$property->name] = $this->compile($property);
        }

        return $properties;
    }

    /**
     * @return list<string>
     *
     * @throws InvalidDocument
     */
    private function required(Node $node): array
    {
        $list = $node->optional('required');
        if ($list === null) {
            return [];
        }

        $names = array_map(static fn (Node $item): string => $item->string(), $list->items());
        if ($names === [] || count(array_unique($names)) !== count($names)) {
            throw $list->invalid('must list at least one name, each once');
        }

        return $names;
    }

    /**
     * @throws InvalidDocument
     */
    private function additionalProperties(Node $node): Schema|bool
    {
        $additional = $node->optional('additionalProperties');

        return match (true) {
            $additional === null => true,
            is_bool($additional->value) => $additional->value,
            default => $this->compile($additional),
        };
    }

    /**
     * @return list<Schema>
     *
     * @throws InvalidDocument
     */
    private function subschemas(Node $node, string $keyword): array
    {
        $list = $node->optional($keyword);
        if ($list === null) {
            return [];
        }

        $schemas = array_map($this->compile(...), $list->items());

        return $schemas === [] ? throw $list->invalid('must list at least one schema') : $schemas;
    }

    /**
     * An ECMA-262 pattern as PCRE: unanchored, as JSON Schema means it, matching code
     * points (`u`). Delimited by `/`, escaping each one the pattern leaves unescaped.
     *
     * @return non-empty-string
     *
     * @throws InvalidDocument When PCRE cannot compile it.
     */
    private static function pattern(string $source, Node $node): string
    {
        $escaped = '';
        $backslashes = 0;
        foreach (mb_str_split($source) as $character) {
            if ($character === '/' && $backslashes % 2 === 0) {
                $escaped .= '\\';
            }
            $backslashes = $character === '\\' ? $backslashes + 1 : 0;
            $escaped .= $character;
        }
        $pattern = '/' . $escaped . '/u';

        if (@preg_match($pattern, '') === false) {
            throw $node->invalid('is not a regular expression PCRE can compile: ' . preg_last_error_msg());
        }

        return $pattern;
    }
}
