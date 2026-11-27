<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authorization;

use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The outline of an OpenFGA model, schema 1.1; whether its relations hold together is the
 * engine's to say (`DecisionEngineContract`).
 */
final class AuthorizationModelTest extends TestCase
{
    public function testAModelIsKeptAsTheJsonItCameAsWithTheTypesItDeclares(): void
    {
        $model = AuthorizationModel::fromJson(DecisionEngineContract::MODEL);

        self::assertSame(DecisionEngineContract::MODEL, $model->json);
        self::assertSame(
            ['user', 'team', 'folder', 'document'],
            array_map(static fn (ObjectType $type): string => $type->value, $model->types),
        );
        self::assertTrue($model->declares(ObjectType::fromString('folder')));
        self::assertFalse($model->declares(ObjectType::fromString('invoice')));
    }

    /** @return iterable<string, array{string}> */
    public static function notModels(): iterable
    {
        yield 'empty' => [''];
        yield 'not JSON' => ['{"schema_version": '];
        yield 'a list' => ['[{"type": "user"}]'];
        yield 'another schema' => ['{"schema_version": "1.0", "type_definitions": [{"type": "user"}]}'];
        yield 'no schema' => ['{"type_definitions": [{"type": "user"}]}'];
        yield 'no types' => ['{"schema_version": "1.1", "type_definitions": []}'];
        yield 'types not a list' => ['{"schema_version": "1.1", "type_definitions": {"a": {"type": "user"}}}'];
        yield 'a type unnamed' => ['{"schema_version": "1.1", "type_definitions": [{"relations": {}}]}'];
        yield 'a type twice' => ['{"schema_version": "1.1", "type_definitions": [{"type": "user"}, {"type": "user"}]}'];
        yield 'a type no engine takes' => ['{"schema_version": "1.1", "type_definitions": [{"type": "us:er"}]}'];
        yield 'past 256 KiB' => [
            '{"schema_version": "1.1", "type_definitions": [{"type": "user"}], "pad": "'
            . str_repeat('x', AuthorizationModel::MAX_BYTES) . '"}',
        ];
    }

    /**
     * A model around `$types`, beside `user` unless one of them is.
     */
    private static function with(string ...$types): string
    {
        $user = array_filter($types, static fn (string $type): bool => str_starts_with($type, '{"type": "user"')) === []
            ? ['{"type": "user"}']
            : [];

        return '{"schema_version": "1.1", "type_definitions": [' . implode(', ', [...$user, ...$types]) . ']}';
    }

    private const string ROLE = '{"type": "role", "relations": {"member": {"this": {}}}, '
        . '"metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}}';

    public function testClaviasTypesAreTakenInTheShapeClaviaWritesThem(): void
    {
        $model = AuthorizationModel::fromJson(self::with(
            self::ROLE,
            str_replace('"role"', '"group"', self::ROLE),
            '{"type": "client"}',
            '{"type": "user", "relations": {}, "metadata": null}',
        ));
        self::assertCount(4, $model->types);

        // As OpenFGA's own transformer writes `define member: [user]`.
        $transformed = '{"type": "role", "relations": {"member": {"this": {}}}, "metadata": {"relations": '
            . '{"member": {"directly_related_user_types": [{"type": "user", "condition": ""}], "module": ""}}}}';
        self::assertTrue(
            AuthorizationModel::fromJson(self::with($transformed))->declares(ObjectType::fromString('role')),
        );
    }

    /** @return iterable<string, array{string}> */
    public static function reservedTypesOutOfShape(): iterable
    {
        yield 'no user' => ['{"schema_version": "1.1", "type_definitions": [{"type": "document"}]}'];
        yield 'a person with a relation' => [self::with(
            '{"type": "user", "relations": {"manager": {"this": {}}}, '
            . '"metadata": {"relations": {"manager": {"directly_related_user_types": [{"type": "user"}]}}}}',
        )];
        yield 'an application with a relation' => [self::with(
            '{"type": "client", "relations": {"owner": {"this": {}}}, '
            . '"metadata": {"relations": {"owner": {"directly_related_user_types": [{"type": "user"}]}}}}',
        )];
        yield 'a role computed from something else' => [self::with(
            '{"type": "role", "relations": {"member": {"union": {"child": [{"this": {}}, '
            . '{"computedUserset": {"relation": "admin"}}]}}, "admin": {"this": {}}}, "metadata": {"relations": '
            . '{"member": {"directly_related_user_types": [{"type": "user"}]}, '
            . '"admin": {"directly_related_user_types": [{"type": "user"}]}}}}',
        )];
        yield 'a role with another relation' => [self::with(str_replace(
            '"relations": {"member": {"this": {}}}',
            '"relations": {"member": {"this": {}}, "owner": {"this": {}}}',
            self::ROLE,
        ))];
        yield 'a role whose members are not people' => [self::with(
            str_replace('[{"type": "user"}]', '[{"type": "user"}, {"type": "team", "relation": "member"}]', self::ROLE),
        )];
        yield 'a role taking every person' => [self::with(
            str_replace('[{"type": "user"}]', '[{"type": "user", "wildcard": {}}]', self::ROLE),
        )];
        yield 'a role under a condition' => [self::with(
            str_replace('[{"type": "user"}]', '[{"type": "user", "condition": "in_office"}]', self::ROLE),
        )];
        yield 'a group with no member' => [self::with('{"type": "group"}')];
    }

    #[DataProvider('reservedTypesOutOfShape')]
    public function testClaviasTypesAreRefusedInAnyOtherShape(string $json): void
    {
        $this->expectException(InvalidValue::class);

        AuthorizationModel::fromJson($json);
    }

    #[DataProvider('notModels')]
    public function testAnythingElseIsRefused(string $json): void
    {
        $this->expectException(InvalidValue::class);

        AuthorizationModel::fromJson($json);
    }
}
