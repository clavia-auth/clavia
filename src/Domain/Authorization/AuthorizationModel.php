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
 * What is checked here is the outline, and Clavia's own rules: the schema version; a list of type
 * definitions, each naming a distinct, valid type; `user` declared; and each {@see ReservedType}
 * declared in the one shape Clavia writes it: `user` and `client` with no relation of their own,
 * `role` and `group` with exactly `member: [user]`, a direct relation with nothing computed into
 * it, so only the relationships Clavia writes make anybody a member. Whether the API's own
 * relations hold together is the decision engine's to say when the model is written.
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
     * @throws InvalidValue When it is not a JSON object of at most 256 KiB, not schema 1.1, its
     *                      type definitions are not a non-empty list of objects naming distinct,
     *                      valid types, it does not declare `user`, or it declares a reserved type
     *                      in another shape than Clavia's.
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
            $reserved = ReservedType::tryFrom($type);
            if ($reserved !== null) {
                /** @var array<array-key, mixed> $definition An array: its type was read above. */
                self::assertReservedShape($reserved, $definition);
            }
        }
        if (! in_array(ReservedType::User->value, $names, true)) {
            throw new InvalidValue('An authorization model declares the type "user": the people Clavia knows.');
        }

        return new self($json, $types);
    }

    /**
     * A reserved type in the shape Clavia writes it: no relation for a person or an application;
     * for a role or a group, `member` alone, direct, taking people alone.
     *
     * @param array<array-key, mixed> $definition
     *
     * @throws InvalidValue
     */
    private static function assertReservedShape(ReservedType $type, array $definition): void
    {
        $relations = $definition['relations'] ?? [];
        /** @var mixed $metadata */
        $metadata = is_array($definition['metadata'] ?? null) ? ($definition['metadata']['relations'] ?? []) : [];

        if ($type->isSubjectOnly()) {
            if ($relations !== [] || $metadata !== []) {
                throw new InvalidValue(sprintf(
                    'The type "%s" is Clavia\'s and has no relation of its own.',
                    $type->value,
                ));
            }

            return;
        }

        // Decoded as arrays, `{"this": {}}` is `['this' => []]`. OpenFGA's own transformer may add
        // empty members (`"condition": ""`) and metadata of its own (`module`, `source_info`).
        /** @var mixed $member */
        $member = is_array($metadata) ? ($metadata['member'] ?? null) : null;
        /** @var mixed $taken */
        $taken = is_array($member) ? ($member['directly_related_user_types'] ?? null) : null;
        /** @var mixed $only */
        $only = is_array($taken) && count($taken) === 1 ? ($taken[0] ?? null) : null;
        if (
            $relations !== ['member' => ['this' => []]]
            || ! is_array($metadata)
            || array_keys($metadata) !== ['member']
            || ! is_array($only)
            || array_filter($only, static fn (mixed $value): bool => $value !== '' && $value !== null)
                !== ['type' => ReservedType::User->value]
        ) {
            throw new InvalidValue(sprintf(
                'The type "%s" is Clavia\'s, declared exactly as "define member: [user]".',
                $type->value,
            ));
        }
    }

    public function declares(ObjectType $type): bool
    {
        return array_any($this->types, static fn (ObjectType $declared): bool => $declared->equals($type));
    }
}
