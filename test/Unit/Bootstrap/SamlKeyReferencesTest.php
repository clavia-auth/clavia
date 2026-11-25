<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Bootstrap;

use Clavia\Bootstrap\SamlKeyReferences;
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use ClaviaTest\Support\TestEnvironment;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Each SAML key reference names one key version for good, in its provider's form, at boot. */
final class SamlKeyReferencesTest extends TestCase
{
    private const string ARN = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-123456789001';
    private const string ARN2 = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-123456789002';

    public function testKeyVersionsArePassed(): void
    {
        // Refused, any of these would throw.
        $this->expectNotToPerformAssertions();
        SamlKeyReferences::check(self::settings([
            'CLAVIA_SAML_KEY_BACKEND' => 'aws-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => self::ARN,
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => self::ARN2,
        ]));
        SamlKeyReferences::check(self::settings([
            'CLAVIA_SAML_KEY_BACKEND' => 'gcp-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => 'projects/p/locations/l/keyRings/r/cryptoKeys/sign/cryptoKeyVersions/1',
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => 'projects/p/locations/l/keyRings/r/cryptoKeys/enc/cryptoKeyVersions/2',
        ]));
        SamlKeyReferences::check(self::settings([]));
    }

    /** @return iterable<string, array{0: array<string, string>}> */
    public static function unusable(): iterable
    {
        yield 'an AWS alias' => [[
            'CLAVIA_SAML_KEY_BACKEND' => 'aws-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => 'alias/clavia-saml',
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => self::ARN2,
        ]];
        yield 'a Cloud KMS key, not a version' => [[
            'CLAVIA_SAML_KEY_BACKEND' => 'gcp-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => 'projects/p/locations/l/keyRings/r/cryptoKeys/sign/cryptoKeyVersions/1',
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => 'projects/p/locations/l/keyRings/r/cryptoKeys/enc',
        ]];
        yield 'an unversioned Key Vault key' => [[
            'CLAVIA_SAML_KEY_BACKEND' => 'azure-key-vault',
            'CLAVIA_SAML_SIGNING_KEY_REF' => 'https://v.vault.azure.net/keys/sign/0123456789abcdef0123456789abcdef',
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => 'https://v.vault.azure.net/keys/enc',
        ]];
        yield 'a retired alias' => [[
            'CLAVIA_SAML_KEY_BACKEND' => 'aws-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => self::ARN,
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => self::ARN2,
            'CLAVIA_SAML_RETIRED_ENCRYPTION_KEY_REFS' => 'alias/old',
        ]];
    }

    /** @param array<string, string> $variables */
    #[DataProvider('unusable')]
    public function testAnythingElseStopsTheServer(array $variables): void
    {
        $this->expectException(InvalidSettings::class);
        SamlKeyReferences::check(self::settings($variables));
    }

    /** @param array<string, string> $variables */
    private static function settings(array $variables): Settings
    {
        return Settings::fromEnvironment(TestEnvironment::variables() + $variables);
    }
}
