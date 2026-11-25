<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Claims;

use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\TestCase;

final class ClaimMappingsTest extends TestCase
{
    public function testTwentyAreAcceptedAndTwentyOneAreNot(): void
    {
        $twenty = array_map(
            static fn (int $i): ClaimMapping => self::mapping('c' . $i, 'constant', (string) $i),
            range(1, 20),
        );
        self::assertCount(20, ClaimMappings::of($twenty)->mappings);

        $this->expectException(InvalidValue::class);
        ClaimMappings::of([...$twenty, self::mapping('c21', 'constant', '21')]);
    }

    public function testTwoOfANameAreRefused(): void
    {
        $this->expectException(InvalidValue::class);

        ClaimMappings::of([self::mapping('plan', 'email'), self::mapping('plan', 'connection')]);
    }

    public function testTwoReadingNestedMetadataAreRefused(): void
    {
        $this->expectException(InvalidValue::class);

        ClaimMappings::of(
            [self::mapping('tenant', 'app_metadata.tenant'), self::mapping('tenant_id', 'app_metadata.tenant.id')],
        );
    }

    public function testTheRolesClaimReadsTheRolesSourceOnly(): void
    {
        self::assertSame('roles', self::mapping('roles', 'roles')->name->value);

        $this->expectException(InvalidValue::class);
        self::mapping('roles', 'app_metadata.roles');
    }

    public function testTheyReadBackFromStorageAsTheyWereSaved(): void
    {
        $mappings = ClaimMappings::of([
            self::mapping('https://example.com/plan', 'app_metadata.plan'),
            self::mapping('roles', 'roles'),
            self::mapping('deployment', 'constant', '{"region":"eu","weights":[1,2.5]}'),
        ]);

        $json = $mappings->toJson();
        self::assertSame($json, ClaimMappings::forApiFromJson($json)->toJson());
        self::assertSame(
            '[{"name":"https://example.com/plan","source":"app_metadata.plan"},{"name":"roles","source":"roles"},'
            . '{"name":"deployment","source":"constant","value":{"region":"eu","weights":[1,2.5]}}]',
            $json,
        );
        self::assertSame('[]', ClaimMappings::none()->toJson());
    }

    public function testAReservedNameSavedEarlierStillLoads(): void
    {
        $loaded = ClaimMappings::forApiFromJson('[{"name":"sub","source":"email"}]');

        self::assertTrue($loaded->mappings[0]->name->isReserved());
    }

    private static function mapping(string $name, string $source, ?string $value = null): ClaimMapping
    {
        return ClaimMapping::forApi(
            ClaimName::fromString($name, onAnApi: true),
            ClaimSource::fromString($source, $value),
        );
    }
}
