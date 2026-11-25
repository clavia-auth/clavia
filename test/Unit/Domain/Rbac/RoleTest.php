<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Rbac;

use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RoleTest extends TestCase
{
    private const string INVOICES = 'rs_invoices00000001';
    private const string REPORTS = 'rs_reports000000001';

    public function testAPermissionGrantedTwiceIsGrantedOnceAndTheyAreKeptInOrder(): void
    {
        $role = self::role('Billing', [
            self::grant(self::REPORTS, 'export'),
            self::grant(self::INVOICES, 'invoices:write'),
            self::grant(self::INVOICES, 'invoices:read'),
            self::grant(self::INVOICES, 'invoices:write'),
        ]);

        self::assertSame(
            ['rs_invoices00000001 invoices:read', 'rs_invoices00000001 invoices:write', 'rs_reports000000001 export'],
            array_map(static fn (GrantedPermission $granted): string => $granted->key(), $role->permissions),
        );
    }

    public function testWhatARoleGrantsIsAskedOfOneApi(): void
    {
        $role = self::role(
            'Billing',
            [self::grant(self::INVOICES, 'invoices:read'), self::grant(self::REPORTS, 'export')],
        );

        self::assertSame('invoices:read', $role->grantsOn(ResourceServerId::fromString(self::INVOICES))->toString());
        self::assertSame('export', $role->grantsOn(ResourceServerId::fromString(self::REPORTS))->toString());
        self::assertTrue($role->grantsOn(ResourceServerId::fromString('rs_elsewhere0000001'))->isEmpty());
    }

    public function testGrantingMoreKeepsWhatItAlreadyGrants(): void
    {
        $role = self::role('Billing', [self::grant(self::INVOICES, 'invoices:read')])
            ->alsoGranting([
                self::grant(self::INVOICES, 'invoices:write'),
                self::grant(self::INVOICES, 'invoices:read'),
            ]);

        self::assertSame(
            'invoices:read invoices:write',
            $role->grantsOn(ResourceServerId::fromString(self::INVOICES))->toString(),
        );
        self::assertSame(
            'invoices:read',
            $role->granting([self::grant(self::INVOICES, 'invoices:read')])
                ->grantsOn(ResourceServerId::fromString(self::INVOICES))
                ->toString(),
        );
    }

    public function testRenamingAndDescribingKeepTheRestOfTheRole(): void
    {
        $role = self::role('Billing', [self::grant(self::INVOICES, 'invoices:read')]);

        $changed = $role->renamed('Accounts')->described('Keeps the books');

        self::assertTrue($changed->id->equals($role->id));
        self::assertSame('Accounts', $changed->name);
        self::assertSame('Keeps the books', $changed->description);
        self::assertEquals($role->permissions, $changed->permissions);
        self::assertEquals($role->createdAt, $changed->createdAt);
    }

    #[DataProvider('invalidNames')]
    public function testANameIsOneLineOfAtMost64Characters(string $name): void
    {
        $this->expectException(InvalidValue::class);

        self::role($name, []);
    }

    /** @return iterable<string, array{string}> */
    public static function invalidNames(): iterable
    {
        yield 'empty' => [''];
        yield 'blank' => ['   '];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'two lines' => ["Billing\nAdmin"];
        yield 'not UTF-8' => ["\xff"];
    }

    public function testADescriptionIsOneLineOfAtMost500Characters(): void
    {
        self::assertSame(str_repeat('é', 500), self::role('Billing', [])->described(str_repeat('é', 500))->description);

        $this->expectException(InvalidValue::class);
        self::role('Billing', [])->described("One\nTwo");
    }

    public function testAnIdIsRolAndSixteenLettersAndDigits(): void
    {
        self::assertMatchesRegularExpression(
            '/^rol_[A-Za-z0-9]{16}$/',
            RoleId::generate(new SecretGenerator(new SeededRandomSource(1)))->value,
        );

        $this->expectException(InvalidValue::class);
        RoleId::fromString('rs_aaaaaaaaaaaaaaaa');
    }

    /** docs/design/scim-provisioning.md §2, §7. */
    public function testAProvisionableRoleHoldsNoPermissionOnASystemApi(): void
    {
        $system = new GrantedPermission(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Scope::fromString('read:users'),
            true,
        );
        $ordinary = self::grant('rs_bbbbbbbbbbbbbbbb', 'read:reports');
        $staff = self::role('Staff', [$ordinary])->withProvisionable(true);

        self::assertTrue($staff->provisionable);
        self::assertTrue($staff->renamed('Employees')->provisionable, 'Kept through a change.');
        foreach (
            [
            static fn (): Role => self::role('Admins', [$system])->withProvisionable(true),
            static fn (): Role => $staff->granting([$ordinary, $system]),
            static fn (): Role => $staff->alsoGranting([$system]),
            ] as $attempt
        ) {
            try {
                $attempt();
                self::fail('A provisionable role on a system API.');
            } catch (InvalidValue $refusal) {
                self::assertStringContainsString('system API', $refusal->getMessage());
            }
        }
        self::assertFalse(self::role('Admins', [$system])->provisionable, 'A role on a system API is fine otherwise.');
    }

    /**
     * @param list<GrantedPermission> $permissions
     */
    private static function role(string $name, array $permissions): Role
    {
        return Role::define(
            RoleId::fromString('rol_aaaaaaaaaaaaaaaa'),
            $name,
            '',
            $permissions,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }

    private static function grant(string $api, string $value): GrantedPermission
    {
        return new GrantedPermission(ResourceServerId::fromString($api), Scope::fromString($value));
    }
}
