<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Claims;

use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Claims\ClaimSourceKind;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimSourceTest extends TestCase
{
    /** @return iterable<string, array{string, ClaimSourceKind}> */
    public static function sources(): iterable
    {
        yield 'email' => ['email', ClaimSourceKind::Email];
        yield 'email_verified' => ['email_verified', ClaimSourceKind::EmailVerified];
        yield 'connection' => ['connection', ClaimSourceKind::Connection];
        yield 'a profile field' => ['profile.given_name', ClaimSourceKind::ProfileField];
        yield 'a metadata path' => ['app_metadata.tenant.id', ClaimSourceKind::AppMetadata];
        yield 'five keys deep' => ['app_metadata.a.b.c.d.e', ClaimSourceKind::AppMetadata];
        yield 'roles' => ['roles', ClaimSourceKind::Roles];
    }

    #[DataProvider('sources')]
    public function testASourceReadsBackAsItWasWritten(string $source, ClaimSourceKind $kind): void
    {
        $read = ClaimSource::fromString($source);

        self::assertSame($kind, $read->kind);
        self::assertSame($source, $read->toString());
    }

    public function testAConstantKeepsItsValueAsCanonicalJson(): void
    {
        $constant = ClaimSource::fromString('constant', '{ "region" : "eu" , "n": 1.0 }');

        self::assertSame(ClaimSourceKind::Constant, $constant->kind);
        self::assertSame('{"n":1.0,"region":"eu"}', $constant->constant, 'Keys sorted, as storage reads it back.');
    }

    /** @return iterable<string, array{string, string|null}> */
    public static function refused(): iterable
    {
        yield 'unknown' => ['address', null];
        yield 'a request parameter' => ['request.audience', null];
        yield 'an unknown profile field' => ['profile.password', null];
        yield 'six keys deep' => ['app_metadata.a.b.c.d.e.f', null];
        yield 'a bad metadata key' => ['app_metadata.the plan', null];
        yield 'an empty metadata key' => ['app_metadata.a..b', null];
        yield 'a constant without a value' => ['constant', null];
        yield 'a constant of null' => ['constant', 'null'];
        yield 'a constant over 1 KiB' => ['constant', '"' . str_repeat('x', 1023) . '"'];
        yield 'a constant that is not JSON' => ['constant', '{eu}'];
        yield 'a value on another source' => ['email', '"x"'];
    }

    #[DataProvider('refused')]
    public function testWhatIsNotASourceIsRefused(string $source, ?string $value): void
    {
        $this->expectException(InvalidValue::class);

        ClaimSource::fromString($source, $value);
    }

    public function testMetadataSourcesOverlapWhenOneReadsInsideTheOther(): void
    {
        $tenant = ClaimSource::fromString('app_metadata.tenant');

        self::assertTrue($tenant->overlaps(ClaimSource::fromString('app_metadata.tenant')));
        self::assertTrue($tenant->overlaps(ClaimSource::fromString('app_metadata.tenant.id')));
        self::assertTrue(ClaimSource::fromString('app_metadata.tenant.id')->overlaps($tenant));
        self::assertFalse($tenant->overlaps(ClaimSource::fromString('app_metadata.tenants')));
        self::assertFalse($tenant->overlaps(ClaimSource::fromString('email')));
    }
}
