<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\ResourceServer;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * APIs, the permissions they define, and the grants that let a client reach them.
 */
final class ResourceServerTest extends TestCase
{
    // ── Identifiers ─────────────────────────────────────────────────────────────

    public function testAGeneratedIdIsPrefixedSoItSaysWhatItNames(): void
    {
        $id = ResourceServerId::generate(new SecretGenerator(new SeededRandomSource(1)));

        self::assertMatchesRegularExpression('/^rs_[A-Za-z0-9]{16}$/D', $id->value);
        self::assertTrue(ResourceServerId::fromString($id->value)->equals($id));
    }

    #[DataProvider('notAnId')]
    public function testAnythingElseIsNotAnId(string $value): void
    {
        $this->expectException(InvalidValue::class);

        ResourceServerId::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notAnId(): iterable
    {
        yield 'another prefix' => ['rol_aaaaaaaaaaaaaaaa'];
        yield 'too short' => ['rs_aaaa'];
        yield 'a trailing newline' => ["rs_aaaaaaaaaaaaaaaa\n"];
    }

    // ── Permissions ─────────────────────────────────────────────────────────────

    public function testPermissionsAreKeptSortedAndAskedForByValue(): void
    {
        $api = $this->api(['invoices:write', 'invoices:read']);

        self::assertSame('invoices:read invoices:write', $api->permissionScopes()->toString());
        self::assertTrue($api->defines('invoices:read'));
        self::assertFalse($api->defines('invoices:delete'));
        self::assertFalse($api->defines('Invoices:read'));
    }

    public function testAPermissionDefinedTwiceIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->api(['invoices:read', 'invoices:read']);
    }

    public function testAnAllDigitPermissionStaysAString(): void
    {
        // PHP would turn the key '10' into the integer 10; the value is never read from a key.
        self::assertSame(['10'], $this->api(['10'])->permissionScopes()->toList());
    }

    #[DataProvider('notAPermission')]
    public function testAPermissionIsAScopeTokenWithAShortDescription(string $value, string $description): void
    {
        $this->expectException(InvalidValue::class);

        Permission::of($value, $description);
    }

    /** @return iterable<string, array{string, string}> */
    public static function notAPermission(): iterable
    {
        yield 'a space' => ['read users', ''];
        yield 'too long' => [str_repeat('a', 129), ''];
        yield 'a description on two lines' => ['read:users', "Read\nusers"];
        yield 'a description too long' => ['read:users', str_repeat('a', 501)];
    }

    // ── The API itself ──────────────────────────────────────────────────────────

    public function testAnIdentifierLongerThan255BytesIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://example.com/' . str_repeat('a', 236)),
            'Too long',
            [],
            new DateTimeImmutable(),
        );
    }

    // ── Client grants ───────────────────────────────────────────────────────────

    public function testAGrantNamesOnlyWhatTheApiDefines(): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessage('does not define: invoices:delete');

        ClientGrant::grant(
            ClientId::fromString('machine'),
            $this->api(['invoices:read']),
            ScopeSet::fromString('invoices:read invoices:delete'),
            new DateTimeImmutable(),
        );
    }

    public function testWhatIsGrantableIsTheGrantNarrowedToWhatTheApiStillDefines(): void
    {
        $api = $this->api(['a', 'b', 'c']);
        $grant = ClientGrant::grant(
            ClientId::fromString('machine'),
            $api,
            ScopeSet::fromString('a b'),
            new DateTimeImmutable(),
        );
        self::assertSame('a b', $grant->grantableOn($api)->toString());

        $shrunk = ResourceServer::register(
            $api->id,
            $api->identifier,
            $api->name,
            [Permission::of('b')],
            $api->createdAt,
        );

        self::assertSame('b', $grant->grantableOn($shrunk)->toString());
    }

    public function testAGrantIsOnlyReadAgainstItsOwnApi(): void
    {
        $grant = ClientGrant::grant(
            ClientId::fromString('machine'),
            $this->api(['a']),
            ScopeSet::fromString('a'),
            new DateTimeImmutable(),
        );
        $other = ResourceServer::register(
            ResourceServerId::fromString('rs_bbbbbbbbbbbbbbbb'),
            Audience::fromString('https://other.example/'),
            'Other',
            [Permission::of('a')],
            new DateTimeImmutable(),
        );

        $this->expectException(InvalidValue::class);

        $grant->grantableOn($other);
    }

    // ── System APIs ─────────────────────────────────────────────────────────────

    public function testAnApiIsNotASystemApiUnlessProvisionedAsOne(): void
    {
        $api = $this->api(['a']);
        self::assertFalse($api->isSystem);

        $system = $api->asSystem('Management', [Permission::of('read:users')]);

        self::assertTrue($system->isSystem);
        self::assertSame('Management', $system->name);
        self::assertSame('read:users', $system->permissionScopes()->toString());
        self::assertTrue($system->id->equals($api->id));
    }

    public function testASystemApiCanBeRenamedAndStaysOne(): void
    {
        $renamed = $this->api(['a'])->asSystem('Management', [])->renamed('Admin');

        self::assertSame('Admin', $renamed->name);
        self::assertTrue($renamed->isSystem);
    }

    public function testASystemApisPermissionsCannotBeReplaced(): void
    {
        $this->expectException(SystemApiProtected::class);

        $this->api([])->asSystem('Management', [Permission::of('a')])->withPermissions([Permission::of('b')]);
    }

    public function testASystemApiCannotBeDeleted(): void
    {
        $ordinary = $this->api(['a']);
        $ordinary->assertDeletable();
        $system = $ordinary->asSystem('Management', []);

        $this->expectException(SystemApiProtected::class);

        $system->assertDeletable();
    }

    public function testAnOrdinaryApisPermissionsAreReplacedAsAWhole(): void
    {
        $api = $this->api(['a', 'b'])->withPermissions([Permission::of('c'), Permission::of('b')]);

        self::assertSame(['b', 'c'], $api->permissionScopes()->toList());
    }

    /**
     * @param list<string> $permissions
     */
    private function api(array $permissions): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://invoices.example/api/'),
            'Invoices',
            array_map(static fn (string $value): Permission => Permission::of($value), $permissions),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
