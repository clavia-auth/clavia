<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Claims;

use Clavia\Domain\Claims\ClaimDestination;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testAnApplicationsMappingSaysWhereItGoes(): void
    {
        $both = ClaimMapping::forApplication(
            ClaimName::fromString('tenant', onAnApi: false),
            ClaimSource::fromString('app_metadata.tenant'),
            [ClaimDestination::UserInfo, ClaimDestination::IdToken],
        );

        self::assertSame(['id_token', 'userinfo'], $both->toArray()['in'] ?? null, 'In a fixed order.');
        self::assertTrue($both->goesTo(ClaimDestination::IdToken));
        self::assertFalse($both->goesTo(ClaimDestination::AccessToken));
        self::assertArrayNotHasKey('in', self::mapping('plan', 'email')->toArray(), "An API's says nothing.");

        $json = ClaimMappings::of([$both])->toJson();
        self::assertSame($json, ClaimMappings::forApplicationFromJson($json)->toJson());
    }

    /** @return iterable<string, array{list<ClaimDestination>}> */
    public static function badDestinations(): iterable
    {
        yield 'nowhere' => [[]];
        yield 'an access token' => [[ClaimDestination::AccessToken]];
        yield 'twice the same' => [[ClaimDestination::IdToken, ClaimDestination::IdToken]];
    }

    /** @param list<ClaimDestination> $destinations */
    #[DataProvider('badDestinations')]
    public function testAnApplicationsMappingGoesSomewhereItMay(array $destinations): void
    {
        $this->expectException(InvalidValue::class);

        ClaimMapping::forApplication(
            ClaimName::fromString('tenant', onAnApi: false),
            ClaimSource::fromString('email'),
            $destinations,
        );
    }

    public function testInIsAListOfIdTokenAndUserinfo(): void
    {
        self::assertSame([ClaimDestination::IdToken], ClaimMappings::destinations(['id_token']));

        $this->expectException(InvalidValue::class);
        ClaimMappings::destinations(['access_token_please']);
    }

    private static function mapping(string $name, string $source, ?string $value = null): ClaimMapping
    {
        return ClaimMapping::forApi(
            ClaimName::fromString($name, onAnApi: true),
            ClaimSource::fromString($source, $value),
        );
    }
}
