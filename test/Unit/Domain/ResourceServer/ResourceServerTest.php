<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\ResourceServer;

use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Contract\DecisionEngineContract;
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
        $this->expectExceptionMessageIsOrContains('does not define: invoices:delete');

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

    public function testRolesAreOffUntilTurnedOnAndSurviveOtherChanges(): void
    {
        $api = $this->api(['a']);
        self::assertFalse($api->enforcePolicies);

        $enforcing = $api->enforcingPolicies(true);

        self::assertTrue($enforcing->enforcePolicies);
        self::assertTrue($enforcing->renamed('Billing')->enforcePolicies);
        self::assertTrue($enforcing->withPermissions([Permission::of('b')])->enforcePolicies);
        self::assertFalse($enforcing->enforcingPolicies(false)->enforcePolicies);
    }

    public function testASystemApiAlwaysEnforcesRoles(): void
    {
        $system = $this->api(['a'])->asSystem('Management', [Permission::of('a')]);
        self::assertTrue($system->enforcePolicies);
        self::assertTrue($system->renamed('Admin')->enforcingPolicies(true)->enforcePolicies);

        $this->expectException(SystemApiProtected::class);
        $system->enforcingPolicies(false);
    }

    public function testASystemApiCannotBeBuiltWithoutRoles(): void
    {
        $this->expectException(InvalidValue::class);

        ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://management.example/api/v1/'),
            'Management',
            [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            isSystem: true,
        );
    }

    public function testFirstPartyApplicationsMaySkipConsentUntilTheApiInsists(): void
    {
        $api = $this->api(['a']);
        self::assertTrue($api->allowSkippingConsent);

        $insisting = $api->allowingConsentSkip(false);

        self::assertFalse($insisting->allowSkippingConsent);
        self::assertFalse($insisting->renamed('Billing')->allowSkippingConsent);
        self::assertFalse($insisting->enforcingPolicies(true)->allowSkippingConsent);
        self::assertFalse($insisting->withPermissions([Permission::of('b')])->allowSkippingConsent);
        self::assertTrue($insisting->allowingConsentSkip(true)->allowSkippingConsent);
    }

    public function testASystemApiNeverAsksForConsent(): void
    {
        $system = $this->api(['a'])->allowingConsentSkip(false)->asSystem('Management', [Permission::of('a')]);
        self::assertTrue($system->allowSkippingConsent, 'Provisioning turns it back on.');
        self::assertTrue($system->allowingConsentSkip(true)->allowSkippingConsent);

        $this->expectException(SystemApiProtected::class);
        $system->allowingConsentSkip(false);
    }

    public function testASystemApiCannotBeBuiltAskingForConsent(): void
    {
        $this->expectException(InvalidValue::class);

        ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://management.example/api/v1/'),
            'Management',
            [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            isSystem: true,
            enforcePolicies: true,
            allowSkippingConsent: false,
        );
    }

    public function testItsCustomClaimsSurviveEveryOtherChange(): void
    {
        $claims = ClaimMappings::of([
            ClaimMapping::forApi(
                ClaimName::fromString('plan', onAnApi: true),
                ClaimSource::fromString('app_metadata.plan'),
            ),
        ]);
        $api = $this->api(['read:invoices'])->withClaims($claims);

        foreach (
            [
            $api->renamed('Billing'),
            $api->withPermissions([Permission::of('read:invoices'), Permission::of('pay:invoices')]),
            $api->enforcingPolicies(true),
            $api->allowingConsentSkip(false),
            $api->issuingAccessTokensAs(AccessTokenFormat::Jwt),
            $api->requiringMfa(MfaPolicy::Required),
            ] as $changed
        ) {
            self::assertSame($claims->toJson(), $changed->claims->toJson());
        }
        self::assertTrue($this->api([])->claims->isEmpty());
    }

    public function testASystemApiTakesNoCustomClaims(): void
    {
        $system = $this->api(['read:users'])->asSystem('Management API', [Permission::of('read:users')]);
        self::assertTrue($system->withClaims(ClaimMappings::none())->claims->isEmpty(), 'None is always allowed.');

        $this->expectException(SystemApiProtected::class);
        $system->withClaims(ClaimMappings::of([
            ClaimMapping::forApi(
                ClaimName::fromString('plan', onAnApi: true),
                ClaimSource::fromString('constant', '"x"'),
            ),
        ]));
    }

    public function testFineGrainedAuthorizationIsSwitchedOnOffAndForgotten(): void
    {
        $api = $this->api(['read:invoices']);
        self::assertNull($api->authorization);
        self::assertFalse($api->authorizes());

        $on = $api->withAuthorization(self::authorization());
        self::assertTrue($on->authorizes());
        // Renamed, the API keeps it: every copy carries it along.
        self::assertTrue($on->renamed('Billing')->requiringMfa(MfaPolicy::Required)->authorizes());

        $off = $on->withAuthorization(self::authorization()->disabled());
        self::assertFalse($off->authorizes());
        self::assertNotNull($off->authorization, 'Switched off, the store is kept.');
        self::assertNull($off->withoutAuthorization()->authorization);
    }

    public function testASystemApiTakesNoFineGrainedAuthorization(): void
    {
        $system = $this->api(['read:users'])->asSystem('Management API', [Permission::of('read:users')]);

        try {
            $system->withAuthorization(self::authorization());
            self::fail('A system API took fine-grained authorization.');
        } catch (SystemApiProtected $refused) {
            self::assertStringContainsString('fine-grained authorization', $refused->getMessage());
        }

        $this->expectException(InvalidValue::class);
        $this->api([])->withAuthorization(self::authorization())->asSystem('Management API', []);
    }

    private static function authorization(): AuthorizationSettings
    {
        return AuthorizationSettings::of(
            true,
            StoreId::fromString('01JAAAAAAAAAAAAAAAAAAAAAAA'),
            AuthorizationModelId::fromString('01JBBBBBBBBBBBBBBBBBBBBBBB'),
            AuthorizationModel::fromJson(DecisionEngineContract::MODEL),
            [ClientId::fromString('invoices-backend')],
            false,
        );
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
