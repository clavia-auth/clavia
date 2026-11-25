<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Provisioning;

use Clavia\Domain\Provisioning\ScimPatch;
use Clavia\Domain\Provisioning\ScimPatchRefused;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

/** RFC 7644 §3.5.2, in the forms of docs/design/scim-provisioning.md §2. */
final class ScimPatchTest extends TestCase
{
    public function testEntraIdsReplacesOfAnAddressAndAName(): void
    {
        $patched = self::apply('[
            {"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "ada.l@contoso.com"},
            {"op": "Replace", "path": "name.familyName", "value": "King"},
            {"op": "Add", "path": "nickName", "value": "Ada"}
        ]');

        self::assertSame('ada.l@contoso.com', $patched->address());
        self::assertSame('King', $patched->familyName);
        self::assertSame('Ada', $patched->givenName, 'The rest of name is kept.');
        self::assertSame('Ada', $patched->nickName);
        self::assertSame('Ada@contoso.com', $patched->userName);
    }

    /** @return iterable<string, array{string}> */
    public static function deactivations(): iterable
    {
        yield 'a boolean' => ['[{"op": "replace", "path": "active", "value": false}]'];
        yield "Entra ID's string" => ['[{"op": "Replace", "path": "active", "value": "False"}]'];
        yield "Okta's, without a path" => ['[{"op": "replace", "value": {"active": false}}]'];
    }

    #[DataProvider('deactivations')]
    public function testEveryFormOfDeactivationDeactivates(string $operations): void
    {
        self::assertFalse(self::apply($operations)->active);
    }

    public function testAStringBooleanIsTakenForActiveAlone(): void
    {
        try {
            self::apply('[{"op": "replace", "path": "emails[type eq \"work\"].primary", "value": "True"}]');
            self::fail('Taken as a boolean.');
        } catch (InvalidValue $refusal) {
            self::assertSame("'emails.primary' is a boolean.", $refusal->getMessage());
        }
    }

    public function testOktasValueWithoutAPathMayNameSubAttributes(): void
    {
        $patched = self::apply('[{"op": "replace", "value": {"name.givenName": "Augusta", "displayName": "A. King"}}]');

        self::assertSame('Augusta', $patched->givenName);
        self::assertSame('Lovelace', $patched->familyName);
        self::assertSame('A. King', $patched->displayName);
    }

    public function testRemoveClearsAndAnExtensionIsLeftAlone(): void
    {
        $patched = self::apply('[
            {"op": "remove", "path": "name.givenName"},
            {"op": "remove", "path": "externalId"},
            {"op": "replace", "value": "x",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"},
            {"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:displayName", "value": "Ada L."}
        ]');

        self::assertNull($patched->givenName);
        self::assertNull($patched->externalId);
        self::assertSame('Ada L.', $patched->displayName);
    }

    public function testAnEmailFilterMatchingNothingAddsTheElementItDescribes(): void
    {
        $patched = self::apply(
            '[{"op": "add", "path": "emails[type eq \"home\"].value", "value": "ada@home.example"}]',
        );

        self::assertSame(['ada@contoso.com', 'ada@home.example'], $patched->emails, 'The primary stays first.');
    }

    public function testTheResourceGivenIsNeverChanged(): void
    {
        $resource = self::ada()->toJson();
        $before = json_encode($resource);

        ScimPatch::fromJson(self::request('[{"op": "replace", "path": "name.familyName", "value": "King"}]'))
            ->applyTo($resource);

        self::assertSame($before, json_encode($resource));
    }

    /** @return iterable<string, array{string, string}> */
    public static function refusals(): iterable
    {
        yield 'no operations' => ['[]', 'invalidSyntax'];
        yield 'another op' => ['[{"op": "move", "path": "active", "value": true}]', 'invalidSyntax'];
        yield 'remove without a path' => ['[{"op": "remove"}]', 'noTarget'];
        yield 'replace without a value' => ['[{"op": "replace", "path": "active"}]', 'invalidSyntax'];
        yield 'no path and no object' => ['[{"op": "replace", "value": false}]', 'invalidSyntax'];
        yield 'an unreadable path' => [
            '[{"op": "replace", "path": "emails[type co \"w\"].value", "value": "x"}]',
            'invalidPath',
        ];
        $add = '{"op": "add", "path": "nickName", "value": "x"}';
        yield 'too many' => ['[' . implode(',', array_fill(0, 101, $add)) . ']', 'invalidSyntax'];
    }

    #[DataProvider('refusals')]
    public function testWhatCannotBeAppliedIsRefusedWithItsType(string $operations, string $scimType): void
    {
        try {
            self::apply($operations);
            self::fail('Applied.');
        } catch (ScimPatchRefused $refusal) {
            self::assertSame($scimType, $refusal->scimType);
        }
    }

    private static function apply(string $operations): ScimUser
    {
        return ScimUser::fromJson(ScimPatch::fromJson(self::request($operations))->applyTo(self::ada()->toJson()));
    }

    private static function request(string $operations): stdClass
    {
        $request = json_decode(
            '{"schemas": ["' . ScimPatch::SCHEMA . '"], "Operations": ' . $operations . '}',
            false,
            16,
            JSON_THROW_ON_ERROR,
        );
        self::assertInstanceOf(stdClass::class, $request);

        return $request;
    }

    private static function ada(): ScimUser
    {
        return ScimUser::fromJson((object) [
            'userName' => 'Ada@contoso.com',
            'externalId' => 'ada',
            'name' => (object) ['givenName' => 'Ada', 'familyName' => 'Lovelace'],
            'emails' => [(object) ['value' => 'ada@contoso.com', 'primary' => true]],
        ]);
    }
}
