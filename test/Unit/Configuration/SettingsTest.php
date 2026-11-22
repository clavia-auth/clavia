<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Configuration;

use Clavia\Configuration\EmailBackend;
use Clavia\Configuration\Environment;
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase
{
    /** @var array<string, string> */
    private const array MINIMAL = ['CLAVIA_ROOT_DOMAIN' => 'acme.com'];

    /**
     * Every development default that must be changed for a real environment to start.
     *
     * @var array<string, string>
     */
    private const array PRODUCTION = [
        'CLAVIA_ROOT_DOMAIN' => 'acme.com',
        'CLAVIA_ENV' => 'production',
        'CLAVIA_EMAIL_BACKEND' => 'smtp',
        'CLAVIA_SMTP_HOST' => 'smtp.acme.com',
        'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
        'CLAVIA_SIGNING_KEY_REF' => 'arn:aws:kms:eu-west-3:000000000000:key/1234',
    ];

    public function testTheRootDomainIsRequired(): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains('CLAVIA_ROOT_DOMAIN is required.');

        Settings::fromEnvironment([]);
    }

    public function testEverythingElseHasADefault(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL);

        self::assertSame(Environment::Development, $settings->env);
        self::assertTrue($settings->isDevelopment());
        self::assertSame('postgres', $settings->signingBackend);
        self::assertSame('RS256', $settings->signingAlgorithm);
        self::assertSame(EmailBackend::Console, $settings->emailBackend);
        self::assertSame(60, $settings->authorizationCodeLifetime);
        self::assertSame(['openid', 'profile', 'email'], $settings->scopesSupported);
        self::assertSame([], $settings->trustedProxies);
        self::assertTrue($settings->sessionCookieSecure);
        self::assertNull($settings->devAutologinEmail);
        self::assertSame([], $settings->warnings());
    }

    public function testEveryHostIsDerivedFromTheRootDomain(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL);

        self::assertSame('auth.acme.com', $settings->authHost());
        self::assertSame('management.acme.com', $settings->managementHost());
        self::assertSame('https://auth.acme.com', $settings->issuer());
        self::assertSame('https://management.acme.com/api/v1/', $settings->managementApiAudience());
    }

    public function testTheRootDomainIsNormalised(): void
    {
        $settings = Settings::fromEnvironment(['CLAVIA_ROOT_DOMAIN' => '  ACME.com. ']);

        self::assertSame('acme.com', $settings->rootDomain);
        self::assertSame('https://auth.acme.com', $settings->issuer());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function domainsThatAreNotBareNames(): iterable
    {
        yield 'a scheme' => ['https://acme.com'];
        yield 'a port' => ['acme.com:8443'];
        yield 'a path' => ['acme.com/idp'];
        yield 'a single label' => ['localhost'];
        yield 'a leading hyphen' => ['-acme.com'];
        yield 'an underscore' => ['ac_me.com'];
    }

    #[DataProvider('domainsThatAreNotBareNames')]
    public function testTheRootDomainMustBeABareDomain(string $domain): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains('CLAVIA_ROOT_DOMAIN must be a bare domain');

        Settings::fromEnvironment(['CLAVIA_ROOT_DOMAIN' => $domain]);
    }

    public function testAnExplicitIssuerLosesItsTrailingSlash(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_ISSUER_URL' => 'https://login.acme.com/']);

        self::assertSame('https://login.acme.com', $settings->issuer());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function issuersThatAreRefused(): iterable
    {
        yield 'not a URL' => ['login.acme.com', 'must be an absolute URL'];
        yield 'a query' => ['https://login.acme.com?tenant=1', 'no query or fragment'];
        yield 'a fragment' => ['https://login.acme.com#top', 'no query or fragment'];
        yield 'plaintext off loopback' => ['http://login.acme.com', 'must use https'];
    }

    #[DataProvider('issuersThatAreRefused')]
    public function testTheIssuerMustBeAnHttpsUrlWithNoQueryOrFragment(string $issuer, string $reason): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains($reason);

        Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_ISSUER_URL' => $issuer]);
    }

    #[DataProvider('loopbackIssuers')]
    public function testAPlaintextIssuerIsAllowedOnLoopbackInDevelopment(string $issuer): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_ISSUER_URL' => $issuer]);

        self::assertSame($issuer, $settings->issuer());
    }

    #[DataProvider('loopbackIssuers')]
    public function testAPlaintextIssuerIsRefusedOutsideDevelopmentEvenOnLoopback(string $issuer): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains('must use https');

        Settings::fromEnvironment(self::PRODUCTION + ['CLAVIA_ISSUER_URL' => $issuer]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function loopbackIssuers(): iterable
    {
        yield 'localhost' => ['http://localhost:8080'];
        yield 'IPv4' => ['http://127.0.0.1:8080'];
        yield 'IPv6' => ['http://[::1]:8080'];
    }

    public function testConnectionUrlsAreAssembledFromTheirParts(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [
            'CLAVIA_POSTGRES_HOST' => 'db',
            'CLAVIA_POSTGRES_PORT' => '5432',
            'CLAVIA_POSTGRES_USER' => 'clavia',
            'CLAVIA_POSTGRES_PASSWORD' => 'p@ss:w/rd',
            'CLAVIA_POSTGRES_DB' => 'idp',
            'CLAVIA_REDIS_HOST' => 'redis',
            'CLAVIA_REDIS_DB' => '2',
        ]);

        self::assertSame('postgresql://clavia:p%40ss%3Aw%2Frd@db:5432/idp', $settings->databaseUrl);
        self::assertSame('redis://redis:6379/2', $settings->redisUrl);
    }

    public function testExplicitConnectionUrlsWin(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [
            'CLAVIA_DATABASE_URL' => 'postgresql://app@rds.internal:5432/clavia',
            'CLAVIA_REDIS_URL' => 'redis://cache.internal:6380/0',
        ]);

        self::assertSame('postgresql://app@rds.internal:5432/clavia', $settings->databaseUrl);
        self::assertSame('redis://cache.internal:6380/0', $settings->redisUrl);
    }

    public function testAnEmptyVariableCountsAsUnset(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [
            'CLAVIA_SECRET_ENCRYPTION_KEY' => '',
            'CLAVIA_ID_TOKEN_LIFETIME' => ' ',
        ]);

        self::assertNull($settings->secretEncryptionKey);
        self::assertSame(300, $settings->idTokenLifetime);
    }

    public function testVariablesWithoutThePrefixAreIgnored(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['ENV' => 'production', 'ROOT_DOMAIN' => 'evil.com']);

        self::assertSame(Environment::Development, $settings->env);
        self::assertSame('acme.com', $settings->rootDomain);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'a word for an integer' => ['CLAVIA_ID_TOKEN_LIFETIME', 'soon', 'must be an integer'];
        yield 'a fraction for an integer' => ['CLAVIA_ID_TOKEN_LIFETIME', '1.5', 'must be an integer'];
        yield 'zero for a lifetime' => ['CLAVIA_ID_TOKEN_LIFETIME', '0', 'must be at least 1'];
        yield 'a long-lived code' => ['CLAVIA_AUTHORIZATION_CODE_LIFETIME', '601', 'must be at most 600'];
        yield 'a port out of range' => ['CLAVIA_POSTGRES_PORT', '70000', 'must be at most 65535'];
        yield 'a negative Redis database' => ['CLAVIA_REDIS_DB', '-1', 'must be at least 0'];
        yield 'too many recovery codes' => ['CLAVIA_MFA_RECOVERY_CODE_COUNT', '21', 'must be at most 20'];
        yield 'a maybe for a boolean' => ['CLAVIA_SOCIAL_AUTO_LINK', 'maybe', 'must be true or false'];
        yield 'an unknown environment' => ['CLAVIA_ENV', 'prod', 'must be one of development, staging, production'];
        yield 'an unknown mail backend' => ['CLAVIA_EMAIL_BACKEND', 'sendmail', 'must be one of console, smtp, none'];
        yield 'a JSON object for a list' => ['CLAVIA_SCOPES_SUPPORTED', '[{"a":1}]', 'must be a list of strings'];
        yield 'broken JSON for a list' => ['CLAVIA_SCOPES_SUPPORTED', '["openid"', 'must be a list of strings'];
        yield 'a hostname for a proxy' => ['CLAVIA_TRUSTED_PROXIES', 'lb.internal', 'must be IP addresses'];
        yield 'an impossible prefix' => ['CLAVIA_TRUSTED_PROXIES', '10.0.0.0/33', 'must be IP addresses'];
    }

    #[DataProvider('malformedValues')]
    public function testAMalformedValueNamesItsVariable(string $variable, string $value, string $reason): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageMatches(
            sprintf('/^%s .*%s/', preg_quote($variable, '/'), preg_quote($reason, '/')),
        );

        Settings::fromEnvironment(self::MINIMAL + [$variable => $value]);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function booleanWords(): iterable
    {
        foreach (['1', 'true', 'TRUE', 't', 'yes', 'Y', 'on'] as $word) {
            yield $word => [$word, true];
        }
        foreach (['0', 'false', 'False', 'f', 'no', 'N', 'off'] as $word) {
            yield $word => [$word, false];
        }
    }

    #[DataProvider('booleanWords')]
    public function testBooleansAcceptTheUsualWords(string $word, bool $expected): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_SOCIAL_AUTO_LINK' => $word]);

        self::assertSame($expected, $settings->socialAutoLink);
    }

    public function testListsAcceptJsonOrSeparators(): void
    {
        $json = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_SCOPES_SUPPORTED' => '["openid", "email"]']);
        $plain = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_SCOPES_SUPPORTED' => 'openid, email  phone']);

        self::assertSame(['openid', 'email'], $json->scopesSupported);
        self::assertSame(['openid', 'email', 'phone'], $plain->scopesSupported);
    }

    public function testTrustedProxiesAreAddressesRangesOrAWildcard(): void
    {
        $listed = Settings::fromEnvironment(
            self::MINIMAL + ['CLAVIA_TRUSTED_PROXIES' => '10.0.0.0/8, 192.168.1.4 fd00::/8'],
        );
        $any = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_TRUSTED_PROXIES' => '10.0.0.1,*']);

        self::assertSame(['10.0.0.0/8', '192.168.1.4', 'fd00::/8'], $listed->trustedProxies);
        self::assertSame(['*'], $any->trustedProxies);
    }

    public function testARemoteSigningBackendNeedsItsKeyReference(): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains("CLAVIA_SIGNING_BACKEND='aws-kms' requires CLAVIA_SIGNING_KEY_REF");

        Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_SIGNING_BACKEND' => 'aws-kms']);
    }

    public function testRetiredKeysAreListedForARemoteBackendOnly(): void
    {
        $remote = ['CLAVIA_SIGNING_BACKEND' => 'aws-kms', 'CLAVIA_SIGNING_KEY_REF' => 'key-3'];

        $settings = Settings::fromEnvironment(
            self::MINIMAL + $remote + ['CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'key-2, key-1'],
        );

        self::assertSame(['key-2', 'key-1'], $settings->signingRetiredKeyRefs);
        self::assertSame([], Settings::fromEnvironment(self::MINIMAL)->signingRetiredKeyRefs);

        $refusals = [
            'the postgres backend retires its own keys' => ['CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'key-1'],
            'never the active one' => $remote + ['CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'key-1,key-3'],
            'each retired key once' => $remote + ['CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'key-1,key-1'],
        ];
        foreach ($refusals as $message => $variables) {
            try {
                Settings::fromEnvironment($variables + self::MINIMAL);
                self::fail($message);
            } catch (InvalidSettings $refused) {
                self::assertStringContainsString($message, $refused->getMessage());
            }
        }
    }

    public function testAnAzureApplicationIsNamedWholeAndProvedOneWay(): void
    {
        $application = [
            'CLAVIA_AZURE_TENANT_ID' => 'tenant',
            'CLAVIA_AZURE_CLIENT_ID' => 'client',
            'CLAVIA_AZURE_CLIENT_SECRET' => 'secret',
        ];
        self::assertSame('secret', Settings::fromEnvironment(self::MINIMAL + $application)->azureClientSecret);
        // A client id alone selects a user-assigned managed identity.
        $identity = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_AZURE_CLIENT_ID' => 'client']);
        self::assertSame('client', $identity->azureClientId);

        $refusals = [
            'not both' => $application + ['CLAVIA_AZURE_FEDERATED_TOKEN_FILE' => '/var/run/token'],
            'needs CLAVIA_AZURE_TENANT_ID and CLAVIA_AZURE_CLIENT_ID' => ['CLAVIA_AZURE_CLIENT_SECRET' => 'secret'],
        ];
        foreach ($refusals as $message => $variables) {
            try {
                Settings::fromEnvironment($variables + self::MINIMAL);
                self::fail($message);
            } catch (InvalidSettings $refused) {
                self::assertStringContainsString($message, $refused->getMessage());
            }
        }
    }

    public function testAProductionConfigurationIsAccepted(): void
    {
        $settings = Settings::fromEnvironment(self::PRODUCTION);

        self::assertSame(Environment::Production, $settings->env);
        self::assertFalse($settings->isDevelopment());
        self::assertSame([], $settings->warnings());
    }

    public function testThePostgresSigningBackendInProductionIsAWarningNotAnError(): void
    {
        $settings = Settings::fromEnvironment([
            'CLAVIA_SIGNING_BACKEND' => 'postgres',
            'CLAVIA_SIGNING_KEY_REF' => '',
        ] + self::PRODUCTION);

        self::assertCount(1, $settings->warnings());
        self::assertStringContainsString('CLAVIA_SIGNING_BACKEND=postgres in production', $settings->warnings()[0]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function developmentOnlyShortcuts(): iterable
    {
        yield 'auto-login' => ['CLAVIA_DEV_AUTOLOGIN_EMAIL', 'dev@acme.com'];
        yield 'insecure session cookie' => ['CLAVIA_SESSION_COOKIE_SECURE', 'false'];
        yield 'console mail' => ['CLAVIA_EMAIL_BACKEND', 'console'];
        yield 'private outbound addresses' => ['CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES', 'true'];
        yield 'a KMS emulator' => ['CLAVIA_AWS_KMS_ENDPOINT_URL', 'http://localhost:4566'];
    }

    #[DataProvider('developmentOnlyShortcuts')]
    public function testDevelopmentShortcutsAreRefusedOutsideDevelopment(string $variable, string $value): void
    {
        foreach (['staging', 'production'] as $env) {
            try {
                /** @var array<string, string> $variables */
                $variables = [$variable => $value, 'CLAVIA_ENV' => $env] + self::PRODUCTION;
                Settings::fromEnvironment($variables);
                self::fail(sprintf('%s=%s was accepted in %s.', $variable, $value, $env));
            } catch (InvalidSettings $refusal) {
                self::assertStringContainsString($variable, $refusal->getMessage());
                self::assertStringContainsString("'" . $env . "'", $refusal->getMessage());
            }
        }
    }

    public function testSmtpWithoutAServerIsRefusedEverywhere(): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains('CLAVIA_EMAIL_BACKEND=smtp requires CLAVIA_SMTP_HOST');

        Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_EMAIL_BACKEND' => 'smtp']);
    }

    public function testTheSenderDefaultsToTheDomain(): void
    {
        self::assertSame('no-reply@acme.com', Settings::fromEnvironment(self::MINIMAL)->emailSender());
        self::assertSame(
            'login@acme.com',
            Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_EMAIL_FROM' => 'login@acme.com'])->emailSender(),
        );
    }

    #[DataProvider('developmentOnlyShortcuts')]
    public function testDevelopmentShortcutsAreAllowedInDevelopment(string $variable, string $value): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [$variable => $value]);

        self::assertTrue($settings->isDevelopment());
    }

    public function testEveryParameterMapsToAPrefixedUpperSnakeCaseVariable(): void
    {
        self::assertSame('CLAVIA_ROOT_DOMAIN', Settings::variableName('rootDomain'));
        self::assertSame('CLAVIA_ENV', Settings::variableName('env'));
        self::assertSame('CLAVIA_AWS_KMS_ENDPOINT_URL', Settings::variableName('awsKmsEndpointUrl'));
        self::assertSame('CLAVIA_SMTP_STARTTLS', Settings::variableName('smtpStarttls'));
    }

    public function testInfrastructureSubdomainsAreReserved(): void
    {
        self::assertSame(['auth', 'management', 'www'], Settings::RESERVED_SUBDOMAIN_LABELS);
        self::assertNotContains('api', Settings::RESERVED_SUBDOMAIN_LABELS);
    }

    // ── Passkeys ────────────────────────────────────────────────────────────────

    public function testPasskeysAreOnAndBoundToTheSignInHostByDefault(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL);

        self::assertTrue($settings->passkeysEnabled);
        self::assertSame('auth.acme.com', $settings->webauthnRpId);
        self::assertSame('acme.com', $settings->webauthnRpName);
        self::assertSame('https://auth.acme.com', $settings->webauthnOrigin());
        self::assertSame(300, $settings->webauthnCeremonyLifetime);
        self::assertSame(10, $settings->passkeyMaxPerUser);
        self::assertSame(600, $settings->passkeyReauthWindow);
        self::assertTrue($settings->passkeySatisfiesMfa);
    }

    public function testTheRelyingPartyFollowsAnExplicitIssuerPortIncluded(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_ISSUER_URL' => 'https://login.acme.com:8443']);

        self::assertSame('login.acme.com', $settings->webauthnRpId);
        self::assertSame('https://login.acme.com:8443', $settings->webauthnOrigin());
    }

    public function testTheRelyingPartyMayBeTheRootDomainAndKeepsItsName(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [
            'CLAVIA_WEBAUTHN_RP_ID' => 'ACME.com.',
            'CLAVIA_WEBAUTHN_RP_NAME' => ' Acme Inc. ',
        ]);

        self::assertSame('acme.com', $settings->webauthnRpId);
        self::assertSame('Acme Inc.', $settings->webauthnRpName);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function relyingPartiesThatAreRefused(): iterable
    {
        yield 'another domain' => ['evil.example'];
        yield 'a public suffix' => ['com'];
        yield 'below the sign-in host' => ['sso.auth.acme.com'];
        yield 'a sibling of the sign-in host' => ['management.acme.com'];
        yield 'not a domain' => ['https://auth.acme.com'];
    }

    #[DataProvider('relyingPartiesThatAreRefused')]
    public function testARelyingPartyNoBrowserWouldAcceptIsRefusedAtStartup(string $rpId): void
    {
        $this->expectException(InvalidSettings::class);
        $this->expectExceptionMessageIsOrContains('CLAVIA_WEBAUTHN_RP_ID');

        Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_WEBAUTHN_RP_ID' => $rpId]);
    }

    public function testWithPasskeysOffTheRelyingPartyIsNotChecked(): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + [
            'CLAVIA_PASSKEYS_ENABLED' => 'false',
            'CLAVIA_WEBAUTHN_RP_ID' => 'evil.example',
        ]);

        self::assertFalse($settings->passkeysEnabled);
    }

    #[DataProvider('loopbackIssuers')]
    public function testAPlaintextLoopbackIssuerTurnsPasskeysOffAndSaysSo(string $issuer): void
    {
        $settings = Settings::fromEnvironment(self::MINIMAL + ['CLAVIA_ISSUER_URL' => $issuer]);

        self::assertFalse($settings->passkeysEnabled);
        self::assertCount(1, $settings->warnings());
        self::assertStringContainsString('Passkeys are off', $settings->warnings()[0]);
    }

    #[DataProvider('passkeyBounds')]
    public function testPasskeyNumbersAreBounded(string $variable, string $value): void
    {
        $this->expectException(InvalidSettings::class);

        Settings::fromEnvironment(self::MINIMAL + [$variable => $value]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function passkeyBounds(): iterable
    {
        yield 'a ceremony too short' => ['CLAVIA_WEBAUTHN_CEREMONY_LIFETIME', '59'];
        yield 'a ceremony too long' => ['CLAVIA_WEBAUTHN_CEREMONY_LIFETIME', '601'];
        yield 'no passkey at all' => ['CLAVIA_PASSKEY_MAX_PER_USER', '0'];
        yield 'too many passkeys' => ['CLAVIA_PASSKEY_MAX_PER_USER', '51'];
        yield 'a window too short' => ['CLAVIA_PASSKEY_REAUTH_WINDOW', '59'];
        yield 'a window too long' => ['CLAVIA_PASSKEY_REAUTH_WINDOW', '86401'];
    }
}
