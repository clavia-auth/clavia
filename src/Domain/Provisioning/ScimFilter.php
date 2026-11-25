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

/**
 * A SCIM filter (RFC 7644 §3.4.2.2), in the subset directories send: `eq` on `userName`,
 * `externalId`, `id` or `emails.value`, joined by `and` (docs/design/scim-provisioning.md §2). A
 * full grammar would be a parser to secure for queries nobody sends; anything else is refused.
 *
 * Attribute names and operators are case-insensitive, and a name may carry the core User schema's
 * URN (`urn:ietf:params:scim:schemas:core:2.0:User:userName`). The value is a JSON string.
 */
final readonly class ScimFilter
{
    private const int MAX_LENGTH = 1024;
    private const int MAX_COMPARISONS = 10;

    /** An attribute path, `eq`, a JSON string, anchored at the offset given. */
    private const string COMPARISON = '/\G\s*((?:urn:ietf:params:scim:schemas:core:2\.0:User:)?[A-Za-z][A-Za-z0-9.]*)'
        . '\s+([A-Za-z]+)\s+("(?:[^"\\\\\x00-\x1F]|\\\\.)*")\s*/i';
    private const string CONJUNCTION = '/\G\s*and\s+/i';
    private const string URN = 'urn:ietf:params:scim:schemas:core:2.0:user:';

    /** @param non-empty-list<array{ScimFilterAttribute, string}> $conditions Every one must hold. */
    private function __construct(public array $conditions)
    {
    }

    /**
     * @throws InvalidValue When the filter is not one of the forms supported.
     */
    public static function parse(string $filter): self
    {
        if ($filter === '' || strlen($filter) > self::MAX_LENGTH) {
            throw new InvalidValue('A filter is 1 to 1024 bytes.');
        }
        $conditions = [];
        $offset = 0;
        while (true) {
            if (preg_match(self::COMPARISON, $filter, $match, 0, $offset) !== 1) {
                throw new InvalidValue(
                    'A filter compares userName, externalId, id or emails.value with eq, joined by and.',
                );
            }
            $offset += strlen($match[0]);
            $conditions[] = [self::attribute($match[1]), self::operand($match[2], $match[3])];
            if (count($conditions) > self::MAX_COMPARISONS) {
                throw new InvalidValue('A filter has at most ten comparisons.');
            }
            if ($offset === strlen($filter)) {
                return new self($conditions);
            }
            if (preg_match(self::CONJUNCTION, $filter, $and, 0, $offset) !== 1) {
                throw new InvalidValue('Comparisons are joined by and; or, not and grouping are not supported.');
            }
            $offset += strlen($and[0]);
        }
    }

    private static function attribute(string $path): ScimFilterAttribute
    {
        $path = strtolower($path);
        if (str_starts_with($path, self::URN)) {
            $path = substr($path, strlen(self::URN));
        }

        return ScimFilterAttribute::tryFrom($path) ?? throw new InvalidValue(
            'A filter compares userName, externalId, id or emails.value.',
        );
    }

    private static function operand(string $operator, string $literal): string
    {
        if (strtolower($operator) !== 'eq') {
            throw new InvalidValue('A filter compares with eq only.');
        }
        /** @var mixed $value */
        $value = json_decode($literal, false, 2);
        if (! is_string($value)) {
            throw new InvalidValue('A filter compares with a JSON string.');
        }

        return $value;
    }
}
