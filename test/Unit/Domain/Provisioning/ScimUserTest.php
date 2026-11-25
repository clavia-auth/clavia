<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Provisioning;

use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

/** RFC 7643 §2.1, §4.1; docs/design/scim-provisioning.md §2. */
final class ScimUserTest extends TestCase
{
    public function testWhatEntraIdSendsIsRead(): void
    {
        $user = self::read('{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
            "externalId": "ada",
            "userName": "Ada@Contoso.com",
            "active": true,
            "displayName": "Ada Lovelace",
            "emails": [{"primary": true, "type": "work", "value": "ada@contoso.com"}],
            "meta": {"resourceType": "User"},
            "name": {"formatted": "Lovelace, Ada", "familyName": "Lovelace", "givenName": "Ada"},
            "title": "Analyst",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Engines"}
        }');

        self::assertSame('Ada@Contoso.com', $user->userName);
        self::assertSame('ada', $user->externalId);
        self::assertTrue($user->active);
        self::assertSame('ada@contoso.com', $user->address());
        self::assertSame('Ada Lovelace', $user->profile()->name, 'The display name first.');
        self::assertSame('Ada', $user->profile()->givenName);
        self::assertSame('Lovelace', $user->profile()->familyName);
        self::assertSame('ada', $user->subject(SubjectAttribute::ExternalId));
        self::assertSame('Ada@Contoso.com', $user->subject(SubjectAttribute::UserName));
    }

    public function testNamesAreCaseInsensitive(): void
    {
        $user = self::read(
            '{"USERNAME": "grace", "Emails": [{"VALUE": "grace@example.com"}], "NAME": {"GIVENNAME": "Grace"}}',
        );

        self::assertSame('grace', $user->userName);
        self::assertSame('grace@example.com', $user->address());
        self::assertSame('Grace', $user->profile()->givenName);
        self::assertNull($user->externalId);
        self::assertTrue($user->active, 'Active unless said otherwise.');
    }

    public function testThePrimaryAddressComesFirstAndUserNameStandsInForNone(): void
    {
        $user = self::read('{"userName": "x", "emails": [
            {"value": "home@example.com"}, {"value": "work@example.com", "primary": true}
        ]}');

        self::assertSame('work@example.com', $user->address());
        self::assertSame('okta@example.com', self::read('{"userName": "okta@example.com"}')->address());
        $this->expectException(InvalidValue::class);
        self::read('{"userName": "no-address"}')->address();
    }

    /** @return iterable<string, array{string, string}> */
    public static function refusals(): iterable
    {
        yield 'no userName' => ['{"emails": [{"value": "a@example.com"}]}', 'userName'];
        yield 'a password' => ['{"userName": "a", "password": "hunter2"}', 'password'];
        yield 'active as a string' => ['{"userName": "a", "active": "True"}', 'active'];
        yield 'userName as a number' => ['{"userName": 42}', 'userName'];
        yield 'a control character' => ['{"userName": "a\u0007b"}', 'userName'];
        yield 'name not an object' => ['{"userName": "a", "name": "Ada"}', 'name'];
        yield 'emails not a list' => ['{"userName": "a", "emails": {"value": "a@example.com"}}', 'emails'];
        yield 'an email not an address' => ['{"userName": "a", "emails": [{"value": "nope"}]}', 'emails.value'];
        yield 'two primaries' => [
            '{"userName": "a", "emails": [{"value": "a@x.y", "primary": true}, {"value": "b@x.y", "primary": true}]}',
            'emails',
        ];
        yield 'a locale that is no tag' => ['{"userName": "a", "locale": "en_US!"}', 'locale'];
        yield 'too long' => ['{"userName": "' . str_repeat('a', 256) . '"}', 'userName'];
    }

    #[DataProvider('refusals')]
    public function testARefusalNamesTheAttributeNeverTheValue(string $json, string $attribute): void
    {
        try {
            self::read($json);
            self::fail('Accepted.');
        } catch (InvalidValue $refusal) {
            self::assertStringContainsString("'" . $attribute, $refusal->getMessage());
            self::assertStringNotContainsString('hunter2', $refusal->getMessage());
            self::assertStringNotContainsString('nope', $refusal->getMessage());
        }
    }

    private static function read(string $json): ScimUser
    {
        $resource = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
        self::assertInstanceOf(stdClass::class, $resource);

        return ScimUser::fromJson($resource);
    }
}
