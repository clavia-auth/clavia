<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Provisioning;

use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** RFC 7644 §3.4.2.2, in the subset of docs/design/scim-provisioning.md §2. */
final class ScimFilterTest extends TestCase
{
    /** @return iterable<string, array{string, list<array{ScimFilterAttribute, string}>}> */
    public static function supported(): iterable
    {
        yield "Entra ID's" => ['userName eq "ada@contoso.com"', [[ScimFilterAttribute::UserName, 'ada@contoso.com']]];
        yield "Entra ID's by externalId" => ['externalId eq "8f3c"', [[ScimFilterAttribute::ExternalId, '8f3c']]];
        yield 'any case' => ['USERNAME EQ "a"', [[ScimFilterAttribute::UserName, 'a']]];
        yield 'with the URN' => [
            'urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"',
            [[ScimFilterAttribute::UserName, 'a']],
        ];
        yield 'an address' => ['emails.value eq "a@example.com"', [[ScimFilterAttribute::EmailValue, 'a@example.com']]];
        yield 'joined' => [
            'id eq "1" and externalId eq "x"',
            [[ScimFilterAttribute::Id, '1'], [ScimFilterAttribute::ExternalId, 'x']],
        ];
        yield 'an escaped quote and an and inside' => [
            'userName eq "a \"and\" b"',
            [[ScimFilterAttribute::UserName, 'a "and" b']],
        ];
        yield 'escapes decoded' => ['userName eq "é"', [[ScimFilterAttribute::UserName, 'é']]];
    }

    /** @param list<array{ScimFilterAttribute, string}> $conditions */
    #[DataProvider('supported')]
    public function testTheFormsDirectoriesSendAreRead(string $filter, array $conditions): void
    {
        self::assertSame($conditions, ScimFilter::parse($filter)->conditions);
    }

    /** @return iterable<string, array{string}> */
    public static function refused(): iterable
    {
        yield 'empty' => [''];
        yield 'another operator' => ['userName co "a"'];
        yield 'or' => ['userName eq "a" or userName eq "b"'];
        yield 'not' => ['not (userName eq "a")'];
        yield 'grouping' => ['(userName eq "a")'];
        yield 'a value path' => ['emails[type eq "work"].value eq "a"'];
        yield 'another attribute' => ['title eq "x"'];
        yield 'a number' => ['id eq 3'];
        yield 'unquoted' => ['userName eq a'];
        yield 'presence' => ['userName pr'];
        yield 'trailing and' => ['userName eq "a" and'];
        yield 'too many' => [implode(' and ', array_fill(0, 11, 'id eq "x"'))];
        yield 'too long' => ['userName eq "' . str_repeat('a', 1024) . '"'];
    }

    #[DataProvider('refused')]
    public function testEverythingElseIsRefused(string $filter): void
    {
        $this->expectException(InvalidValue::class);

        ScimFilter::parse($filter);
    }
}
