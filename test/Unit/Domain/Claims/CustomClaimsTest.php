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
use Clavia\Domain\Claims\ClaimSubject;
use Clavia\Domain\Claims\CustomClaims;
use Clavia\Domain\Claims\CustomClaimsTooLarge;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;
use stdClass;

final class CustomClaimsTest extends TestCase
{
    public function testEachSourceReadsTheAccount(): void
    {
        $claims = CustomClaims::of(self::mappings([
            ['https://example.com/email', 'email'],
            ['verified', 'email_verified'],
            ['via', 'connection'],
            ['first_name', 'profile.given_name'],
            ['plan', 'app_metadata.plan'],
            ['tenant', 'app_metadata.tenant'],
            ['roles', 'roles'],
            ['deployment', 'constant', '"eu-1"'],
        ]), new ClaimSubject(self::ada(), ['Billing', 'Reports']), ClaimDestination::AccessToken);

        self::assertSame('ada@example.com', $claims['https://example.com/email']);
        self::assertFalse($claims['verified']);
        self::assertSame('password', $claims['via']);
        self::assertSame('Ada', $claims['first_name']);
        self::assertSame('pro', $claims['plan']);
        self::assertEquals((object) ['id' => 42, 'region' => 'eu'], $claims['tenant']);
        self::assertSame(['Billing', 'Reports'], $claims['roles']);
        self::assertSame('eu-1', $claims['deployment']);
    }

    public function testASourceWithNoValueLeavesItsClaimOut(): void
    {
        $claims = CustomClaims::of(self::mappings([
            ['nick', 'profile.nickname'],
            ['missing', 'app_metadata.nothing.here'],
            ['nulled', 'app_metadata.cleared'],
            ['roles', 'roles'],
        ]), new ClaimSubject(self::ada(), []), ClaimDestination::AccessToken);

        self::assertSame([], $claims, 'Never null, never an empty list of roles.');
    }

    public function testATokenWithNoPersonTakesConstantsOnly(): void
    {
        $claims = CustomClaims::of(self::mappings([
            ['plan', 'app_metadata.plan'],
            ['deployment', 'constant', '{"region":"eu"}'],
        ]), null, ClaimDestination::AccessToken);

        self::assertEquals(['deployment' => (object) ['region' => 'eu']], $claims);
    }

    public function testAMappingGoesOnlyWhereItIsMeantTo(): void
    {
        self::assertSame([], CustomClaims::of(
            self::mappings([['deployment', 'constant', '"eu-1"']]),
            null,
            ClaimDestination::IdToken,
        ));
    }

    public function testAReservedNameSavedEarlierNeverReachesAToken(): void
    {
        $this->expectException(LogicException::class);

        CustomClaims::of(
            ClaimMappings::forApiFromJson('[{"name":"sub","source":"email"}]'),
            new ClaimSubject(self::ada(), []),
            ClaimDestination::AccessToken,
        );
    }

    public function testPastTheCapTheTokenIsRefusedRatherThanCut(): void
    {
        $big = new stdClass();
        $big->blob = str_repeat('x', 16_000);
        $ada = self::ada();
        $ada->changeAppMetadata(AppMetadata::fromJson((string) json_encode($big)), new DateTimeImmutable());
        $rows = [['blob', 'app_metadata.blob']];
        foreach (range(1, 17) as $i) {
            $rows[] = ['c' . $i, 'constant', '"' . str_repeat('y', 1000) . '"'];
        }

        $this->expectException(CustomClaimsTooLarge::class);
        CustomClaims::of(self::mappings($rows), new ClaimSubject($ada, []), ClaimDestination::AccessToken);
    }

    /** @param list<array{0: string, 1: string, 2?: string}> $rows */
    private static function mappings(array $rows): ClaimMappings
    {
        return ClaimMappings::of(array_map(
            static fn (array $row): ClaimMapping => ClaimMapping::forApi(
                ClaimName::fromString($row[0], onAnApi: true),
                ClaimSource::fromString($row[1], $row[2] ?? null),
            ),
            $rows,
        ));
    }

    private static function ada(): User
    {
        $ada = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'ada@example.com',
            null,
            new DateTimeImmutable(),
        );
        $ada->changeProfile(Profile::of('Ada Lovelace', 'Ada', 'Lovelace', null, null, null), new DateTimeImmutable());
        $ada->changeAppMetadata(
            AppMetadata::fromJson('{"plan":"pro","tenant":{"region":"eu","id":42},"cleared":null}'),
            new DateTimeImmutable(),
        );

        return $ada;
    }
}
