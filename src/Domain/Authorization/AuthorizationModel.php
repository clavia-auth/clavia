<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * An authorization model in OpenFGA's JSON form, schema 1.1: the types of a store, their
 * relations and how each is worked out (docs/design/fine-grained-authorization.md §2, "Models").
 *
 * Only the outline is checked here: the schema version, and a list of type definitions, each
 * naming a distinct, valid type. Whether the relations hold together is the decision engine's to
 * say when the model is written; the reserved types' rules are Clavia's, and come with the
 * models' Management API.
 */
final readonly class AuthorizationModel
{
    public const string SCHEMA_VERSION = '1.1';

    /** The largest model taken, in bytes of JSON: OpenFGA's own limit is 256 KiB. */
    public const int MAX_BYTES = 262144;

    /**
     * @param non-empty-string $json
     * @param non-empty-list<ObjectType> $types
     */
    private function __construct(
        public string $json,
        public array $types,
    ) {
    }

    /**
     * The model as OpenFGA's API takes it, `schema_version`, `type_definitions` and optionally
     * `conditions`, kept as the JSON text it came as: decoded into PHP arrays, its empty objects
     * (`"this": {}`) would come back as empty lists, which the engine does not read as the same.
     *
     * @throws InvalidValue When it is not a JSON object of at most 256 KiB, not schema 1.1, or its
     *                      type definitions are not a non-empty list of objects naming distinct,
     *                      valid types.
     */
    public static function fromJson(string $json): self
    {
        if ($json === '' || strlen($json) > self::MAX_BYTES) {
            throw new InvalidValue('An authorization model is a JSON object of at most 256 KiB.');
        }
        try {
            $document = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidValue('An authorization model is a JSON object of at most 256 KiB.');
        }
        if (! is_array($document) || array_is_list($document)) {
            throw new InvalidValue('An authorization model is a JSON object of at most 256 KiB.');
        }
        if (($document['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw new InvalidValue('An authorization model is schema version 1.1.');
        }
        $definitions = $document['type_definitions'] ?? null;
        if (! is_array($definitions) || $definitions === [] || ! array_is_list($definitions)) {
            throw new InvalidValue('An authorization model has a non-empty list of type definitions.');
        }

        $types = [];
        $names = [];
        /** @var mixed $definition */
        foreach ($definitions as $definition) {
            $type = is_array($definition) ? ($definition['type'] ?? null) : null;
            if (! is_string($type)) {
                throw new InvalidValue('Every type definition names its type.');
            }
            if (in_array($type, $names, true)) {
                throw new InvalidValue('An authorization model defines each type once.');
            }
            $names[] = $type;
            $types[] = ObjectType::fromString($type);
        }

        return new self($json, $types);
    }

    public function declares(ObjectType $type): bool
    {
        return array_any($this->types, static fn (ObjectType $declared): bool => $declared->equals($type));
    }
}
