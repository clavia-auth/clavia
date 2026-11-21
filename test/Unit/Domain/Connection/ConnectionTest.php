<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Connection;

use Clavia\Domain\Connection\BuiltInConnection;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConnectionTest extends TestCase
{
    #[DataProvider('names')]
    public function testANameIsLowerCaseLettersDigitsAndDashesStartingWithALetter(string $name, bool $valid): void
    {
        if (! $valid) {
            $this->expectException(InvalidValue::class);
        }

        self::assertSame($name, ConnectionName::fromString($name)->value);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function names(): iterable
    {
        yield 'a word' => ['password', true];
        yield 'with digits and dashes' => ['acme-sso-2', true];
        yield 'one letter' => ['a', true];
        yield '32 characters' => [str_repeat('a', 32), true];
        yield '33 characters' => [str_repeat('a', 33), false];
        yield 'empty' => ['', false];
        yield 'upper case' => ['Google', false];
        yield 'starting with a digit' => ['2fa', false];
        yield 'starting with a dash' => ['-acme', false];
        yield 'an underscore' => ['acme_sso', false];
        yield 'a slash' => ['acme/sso', false];
        yield 'a trailing newline' => ["acme\n", false];
    }

    public function testThePoolsAndProvidersOfTheCodeAreBuiltInAndNotDeleted(): void
    {
        foreach ([$this->pool(ConnectionName::DEFAULT_POOL), $this->social('google')] as $builtIn) {
            self::assertTrue($builtIn->isBuiltIn());
            try {
                $builtIn->assertDeletable();
                self::fail(sprintf("'%s' could be deleted.", $builtIn->name->value));
            } catch (BuiltInConnection $refused) {
                self::assertStringContainsString('switch it off', $refused->getMessage());
            }
        }
    }

    public function testAnOperatorsPoolOrProviderMayBeDeleted(): void
    {
        $this->expectNotToPerformAssertions();

        $this->pool('staff')->assertDeletable();
        $this->oidc()->assertDeletable();
    }

    public function testWhatAConnectionIs(): void
    {
        self::assertTrue($this->pool('staff')->isDatabase());
        self::assertFalse($this->pool('staff')->isExternal());
        self::assertTrue($this->social('github')->isExternal());
        self::assertTrue($this->oidc()->isExternal());
        self::assertFalse($this->oidc()->isDatabase());
    }

    public function testSwitchingChangesOnlyWhatItNames(): void
    {
        $connection = $this->oidc();

        $off = $connection->switched(false, null, null);
        $renamed = $connection->switched(null, true, 'Acme Corporate SSO');

        self::assertFalse($off->isEnabled);
        self::assertFalse($off->isDomainConnection);
        self::assertSame('Acme', $off->displayName);
        self::assertTrue($renamed->isEnabled);
        self::assertTrue($renamed->isDomainConnection);
        self::assertSame('Acme Corporate SSO', $renamed->displayName);
        self::assertSame($connection->oidc, $renamed->oidc);
        self::assertSame(ConnectionStrategy::Oidc, $renamed->strategy);
    }

    #[DataProvider('displayNames')]
    public function testADisplayNameIsOneLineOfAtMost120Characters(string $displayName): void
    {
        $this->expectException(InvalidValue::class);

        $this->pool('staff')->switched(null, null, $displayName);
    }

    /** @return iterable<string, array{string}> */
    public static function displayNames(): iterable
    {
        yield 'blank' => ['   '];
        yield 'two lines' => ["Staff\nPool"];
        yield '121 characters' => [str_repeat('é', 121)];
        yield 'not UTF-8' => ["\xC3\x28"];
    }

    public function testOnlyAnOidcConnectionHasProviderSettings(): void
    {
        $refused = false;
        try {
            Connection::reconstitute(
                ConnectionName::fromString('acme'),
                'Acme',
                ConnectionStrategy::Oidc,
                true,
                false,
                null,
                new DateTimeImmutable(),
            );
        } catch (InvalidValue) {
            $refused = true;
        }
        self::assertTrue($refused, 'An OIDC connection without settings was made.');

        $this->expectException(InvalidValue::class);

        $this->pool('staff')->withOidc(self::settings());
    }

    public function testAnOidcProviderIsReachedOverHttpsAndAsksForOpenId(): void
    {
        $refused = 0;
        foreach (
            [
                static fn (): OidcSettings => self::settings(issuer: 'http://idp.example'),
                static fn (): OidcSettings => self::settings(scope: 'email profile'),
                static fn (): OidcSettings => self::settings(clientId: ''),
                static fn (): OidcSettings => self::settings(secret: ''),
            ] as $unusable
        ) {
            try {
                $unusable();
            } catch (InvalidValue) {
                ++$refused;
            }
        }
        self::assertSame(4, $refused, 'Unusable settings were accepted.');

        self::assertSame('connection:acme', OidcSettings::secretContext(ConnectionName::fromString('acme')));
    }

    private function pool(string $name): Connection
    {
        return Connection::pool(ConnectionName::fromString($name), 'Pool', true, false, new DateTimeImmutable());
    }

    private function social(string $name): Connection
    {
        return Connection::reconstitute(
            ConnectionName::fromString($name),
            ucfirst($name),
            ConnectionStrategy::Social,
            true,
            false,
            null,
            new DateTimeImmutable(),
        );
    }

    private function oidc(): Connection
    {
        return Connection::openIdProvider(
            ConnectionName::fromString('acme'),
            'Acme',
            self::settings(),
            true,
            false,
            new DateTimeImmutable(),
        );
    }

    private static function settings(
        string $issuer = 'https://idp.example',
        string $scope = 'openid email',
        string $clientId = 'clavia',
        string $secret = 'sealed',
    ): OidcSettings {
        return OidcSettings::of(
            $issuer,
            $clientId,
            $secret,
            ScopeSet::fromString($scope),
            'https://idp.example/authorize',
            'https://idp.example/token',
            'https://idp.example/jwks',
        );
    }
}
