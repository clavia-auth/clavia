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

    #[DataProvider('notModels')]
    public function testAnythingElseIsRefused(string $json): void
    {
        $this->expectException(InvalidValue::class);

        AuthorizationModel::fromJson($json);
    }
}
