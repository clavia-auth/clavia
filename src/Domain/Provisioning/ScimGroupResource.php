<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Shared\InvalidValue;
use stdClass;

/**
 * A SCIM `Group` resource as a directory sends it (RFC 7643 §4.2), read for what this server keeps
 * (docs/design/scim-provisioning.md §5.5): `displayName` (required), `externalId`, and `members`,
 * each named by its `value`, the `id` of a `User`. Attribute names are case-insensitive; anything
 * else is ignored. Every refusal names the attribute, never the value.
 */
final readonly class ScimGroupResource
{
    public const string SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    /** A group holds at most this many members: a bound on the work one request causes. */
    public const int MAX_MEMBERS = 10_000;

    private const int MAX_LENGTH = 255;

    /**
     * @param non-empty-string       $displayName
     * @param non-empty-string|null  $externalId
     * @param list<non-empty-string> $members     The members' ids as sent, each once.
     */
    private function __construct(
        public string $displayName,
        public ?string $externalId,
        public array $members,
    ) {
    }

    /**
     * @throws InvalidValue When `displayName` is missing, or an attribute has the wrong shape.
     */
    public static function fromJson(stdClass $resource): self
    {
        $attributes = array_change_key_case(get_object_vars($resource));
        $displayName = self::text($attributes['displayname'] ?? null, 'displayName')
            ?? throw new InvalidValue("'displayName' is required.");
        $members = $attributes['members'] ?? null;
        if ($members !== null && (! is_array($members) || ! array_is_list($members))) {
            throw new InvalidValue("'members' is an array of objects.");
        }
        $ids = [];
        /** @var mixed $member */
        foreach ($members ?? [] as $member) {
            if (! $member instanceof stdClass) {
                throw new InvalidValue("'members' is an array of objects.");
            }
            $value = self::text(array_change_key_case(get_object_vars($member))['value'] ?? null, 'members.value')
                ?? throw new InvalidValue("'members.value' is required: the id of a User.");
            $ids[$value] = $value;
        }
        if (count($ids) > self::MAX_MEMBERS) {
            throw new InvalidValue(sprintf("A group has at most %d 'members'.", self::MAX_MEMBERS));
        }

        return new self(
            $displayName,
            self::text($attributes['externalid'] ?? null, 'externalId'),
            array_values($ids),
        );
    }

    /** The resource as JSON, with what this server keeps: what a `PATCH` is applied to. */
    public function toJson(): stdClass
    {
        return (object) array_filter([
            'schemas' => [self::SCHEMA],
            'displayName' => $this->displayName,
            'externalId' => $this->externalId,
            'members' => array_map(static fn (string $id): stdClass => (object) ['value' => $id], $this->members),
        ], static fn (mixed $value): bool => $value !== null);
    }

    /** @return non-empty-string|null */
    private static function text(mixed $value, string $name): ?string
    {
        if ($value === null) {
            return null;
        }
        if (
            ! is_string($value)
            || ! mb_check_encoding($value, 'UTF-8')
            || mb_strlen($value, 'UTF-8') > self::MAX_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new InvalidValue(sprintf(
                "'%s' is a string of at most %d characters, without control characters.",
                $name,
                self::MAX_LENGTH,
            ));
        }

        return $value === '' ? null : $value;
    }
}
