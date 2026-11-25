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
 * A SCIM `PATCH` (RFC 7644 §3.5.2), in the forms Entra ID and Okta send
 * (docs/design/scim-provisioning.md §2): `add`, `replace` and `remove`, with no path (an object of
 * attributes) or a path of `attr`, `attr.sub`, or a value filter on `emails` (`emails[type eq
 * "work"].value`, `emails[primary eq true].value`).
 *
 * The operations are applied in order to the resource as it stands ({@see ScimUser::toJson()}), and
 * the result is read again as a whole `ScimUser`, held to the same rules as a `POST` or a `PUT`.
 * Operation names and attribute names are case-insensitive. A path naming an attribute this server
 * does not keep (an extension's, `title`) changes nothing, as such an attribute is ignored anywhere.
 * `"True"` and `"False"` as strings are taken for `active` alone: a documented quirk of Entra ID's
 * client, accepted for that one attribute, by name.
 */
final readonly class ScimPatch
{
    public const string SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

    private const int MAX_OPERATIONS = 100;
    private const array URNS = [
        'urn:ietf:params:scim:schemas:core:2.0:user:',
        'urn:ietf:params:scim:schemas:core:2.0:group:',
    ];

    /** `attr`, `attr.sub`, or `attr[sub eq value]` with an optional `.sub` after it. */
    private const string PATH = '/^([A-Za-z][A-Za-z0-9\-_]*)(?:\.([A-Za-z][A-Za-z0-9\-_]*))?'
        . '(?:\[\s*([A-Za-z][A-Za-z0-9]*)\s+eq\s+("(?:[^"\\\\]|\\\\.)*"|true|false)\s*\]'
        . '(?:\.([A-Za-z][A-Za-z0-9]*))?)?$/Di';

    /** The multi-valued attributes of the resource: an `add` appends to them. */
    private const array MULTI_VALUED = ['emails', 'members'];

    /** @param non-empty-list<array{op: 'add'|'replace'|'remove', path: ?string, value: mixed}> $operations */
    private function __construct(private array $operations)
    {
    }

    /**
     * @throws ScimPatchRefused When the request is not a list of operations of the forms supported.
     */
    public static function fromJson(stdClass $request): self
    {
        $members = array_change_key_case(get_object_vars($request));
        $operations = $members['operations'] ?? null;
        if (! is_array($operations) || ! array_is_list($operations) || $operations === []) {
            throw ScimPatchRefused::syntax("'Operations' is a list of one or more operations.");
        }
        if (count($operations) > self::MAX_OPERATIONS) {
            throw ScimPatchRefused::syntax('A PATCH has at most one hundred operations.');
        }
        $read = [];
        /** @var mixed $operation */
        foreach ($operations as $operation) {
            if (! $operation instanceof stdClass) {
                throw ScimPatchRefused::syntax('Each operation is an object.');
            }
            $fields = array_change_key_case(get_object_vars($operation));
            /** @var mixed $name */
            $name = $fields['op'] ?? null;
            $op = is_string($name) ? strtolower($name) : null;
            if ($op !== 'add' && $op !== 'replace' && $op !== 'remove') {
                throw ScimPatchRefused::syntax("'op' is add, replace or remove.");
            }
            $path = $fields['path'] ?? null;
            if ($path !== null && (! is_string($path) || trim($path) === '')) {
                throw ScimPatchRefused::path("'path' is a string naming an attribute.");
            }
            if ($op === 'remove' && $path === null) {
                throw ScimPatchRefused::noTarget('A remove names its target with a path.');
            }
            if ($op !== 'remove' && ! array_key_exists('value', $fields)) {
                throw ScimPatchRefused::syntax("An add or a replace carries a 'value'.");
            }
            if ($path === null && ! $fields['value'] instanceof stdClass) {
                throw ScimPatchRefused::syntax('Without a path, the value is an object of attributes.');
            }
            $read[] = ['op' => $op, 'path' => $path === null ? null : trim($path), 'value' => $fields['value'] ?? null];
        }

        return new self($read);
    }

    /**
     * The resource with every operation applied, in order.
     *
     * @throws ScimPatchRefused When a path cannot be read.
     * @throws InvalidValue     When a filtered attribute holds something else than objects.
     */
    public function applyTo(stdClass $resource): stdClass
    {
        $document = self::copy($resource);
        foreach ($this->operations as ['op' => $op, 'path' => $path, 'value' => $value]) {
            if ($path === null) {
                assert($value instanceof stdClass);
                /** @var mixed $member */
                foreach (get_object_vars($value) as $name => $member) {
                    // Okta sends dotted names in a value without a path ("name.givenName").
                    $this->at($document, $op, (string) $name, $member);
                }
                continue;
            }
            $this->at($document, $op, $path, $value);
        }

        return $document;
    }

    private function at(stdClass $document, string $op, string $path, mixed $value): void
    {
        foreach (self::URNS as $urn) {
            $path = str_starts_with(strtolower($path), $urn) ? substr($path, strlen($urn)) : $path;
        }
        if (str_starts_with(strtolower($path), 'urn:')) {
            return; // An extension's attribute: not kept, so not changed.
        }
        if (preg_match(self::PATH, $path, $match) !== 1) {
            throw ScimPatchRefused::path('A path is attr, attr.sub, or emails[type eq "work"].value.');
        }
        $attribute = $match[1];
        $sub = ($match[2] ?? '') === '' ? null : $match[2];
        if (($match[3] ?? '') !== '') {
            $sub = ($match[5] ?? '') === '' ? null : $match[5];
            $this->filtered($document, $op, $attribute, $match[3], $match[4], $sub, $value);

            return;
        }
        if (strtolower($attribute) === 'active') {
            /** @var mixed $value */
            $value = self::active($value);
        }
        if ($sub !== null) {
            /** @var mixed $parent */
            $parent = self::get($document, $attribute);
            if (! $parent instanceof stdClass) {
                if ($op === 'remove') {
                    return;
                }
                $parent = new stdClass();
                self::set($document, $attribute, $parent);
            }
            $op === 'remove' ? self::unset($parent, $sub) : self::set($parent, $sub, $value);

            return;
        }
        if ($op === 'remove') {
            self::unset($document, $attribute);

            return;
        }
        if ($op === 'add' && in_array(strtolower($attribute), self::MULTI_VALUED, true)) {
            /** @var mixed $current */
            $current = self::get($document, $attribute);
            $added = is_array($value) ? $value : [$value];
            self::set($document, $attribute, [...(is_array($current) ? $current : []), ...$added]);

            return;
        }
        if ($op === 'add' && $value instanceof stdClass && self::get($document, $attribute) instanceof stdClass) {
            // Adding to a complex attribute merges its sub-attributes (RFC 7644 §3.5.2.1).
            $merged = self::get($document, $attribute);
            assert($merged instanceof stdClass);
            /** @var mixed $member */
            foreach (get_object_vars($value) as $name => $member) {
                self::set($merged, (string) $name, $member);
            }

            return;
        }
        self::set($document, $attribute, $value);
    }

    /**
     * `attr[field eq literal].sub`: the elements of a multi-valued attribute the filter matches.
     *
     * @throws InvalidValue When an element, or a whole element given, is not an object.
     */
    private function filtered(
        stdClass $document,
        string $op,
        string $attribute,
        string $field,
        string $literal,
        ?string $sub,
        mixed $value,
    ): void {
        /** @var mixed $expected A JSON string, or `true` or `false` in any case. */
        $expected = match (strtolower($literal)) {
            'true' => true,
            'false' => false,
            default => json_decode($literal, false, 2),
        };
        if ($sub === null && $op !== 'remove' && ! $value instanceof stdClass) {
            throw new InvalidValue(sprintf("'%s' is an array of objects.", $attribute));
        }
        $matched = false;
        $kept = [];
        foreach (self::elements($document, $attribute) as $element) {
            if (! self::matches(self::get($element, $field), $expected)) {
                $kept[] = $element;
                continue;
            }
            $matched = true;
            if ($op === 'remove' && $sub === null) {
                continue;
            }
            if ($sub === null) {
                assert($value instanceof stdClass);
                $kept[] = self::copy($value);
                continue;
            }
            $op === 'remove' ? self::unset($element, $sub) : self::set($element, $sub, $value);
            $kept[] = $element;
        }
        if (! $matched && $op !== 'remove') {
            // Nothing matched: the element the filter describes is added (Entra ID's "work" email).
            $element = $value instanceof stdClass && $sub === null ? self::copy($value) : new stdClass();
            self::set($element, $field, $expected);
            if ($sub !== null) {
                self::set($element, $sub, $value);
            }
            $kept[] = $element;
        }
        self::set($document, $attribute, $kept);
    }

    /**
     * The elements of a multi-valued attribute, none when it has no value.
     *
     * @return list<stdClass>
     *
     * @throws InvalidValue When one is not an object.
     */
    private static function elements(stdClass $document, string $attribute): array
    {
        /** @var mixed $current */
        $current = self::get($document, $attribute);
        if ($current === null) {
            return [];
        }
        if (! is_array($current)) {
            throw new InvalidValue(sprintf("'%s' is an array of objects.", $attribute));
        }
        $elements = [];
        /** @var mixed $element */
        foreach ($current as $element) {
            if (! $element instanceof stdClass) {
                throw new InvalidValue(sprintf("'%s' is an array of objects.", $attribute));
            }
            $elements[] = $element;
        }

        return $elements;
    }

    private static function matches(mixed $actual, mixed $expected): bool
    {
        return is_string($actual) && is_string($expected)
            ? strtolower($actual) === strtolower($expected)
            : $actual === $expected;
    }

    /** `active` as a boolean, or Entra ID's `"True"` and `"False"`. */
    private static function active(mixed $value): mixed
    {
        if (is_string($value) && in_array(strtolower($value), ['true', 'false'], true)) {
            return strtolower($value) === 'true';
        }

        return $value;
    }

    /** The member named so, ignoring case. */
    private static function get(stdClass $object, string $name): mixed
    {
        /** @var mixed $member */
        foreach (get_object_vars($object) as $key => $member) {
            if (strcasecmp((string) $key, $name) === 0) {
                return $member;
            }
        }

        return null;
    }

    /** Set a member, replacing any of the same name in another case. */
    private static function set(stdClass $object, string $name, mixed $value): void
    {
        self::unset($object, $name);
        $object->{$name} = $value;
    }

    private static function unset(stdClass $object, string $name): void
    {
        foreach (array_keys(get_object_vars($object)) as $key) {
            if (strcasecmp((string) $key, $name) === 0) {
                unset($object->{$key});
            }
        }
    }

    /** A deep copy, so the resource given is never changed. */
    private static function copy(stdClass $object): stdClass
    {
        $copy = json_decode(json_encode($object, JSON_THROW_ON_ERROR), false, 32, JSON_THROW_ON_ERROR);
        assert($copy instanceof stdClass);

        return $copy;
    }
}
