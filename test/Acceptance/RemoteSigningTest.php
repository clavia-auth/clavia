<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\Signing\Remote\RemoteTokenSigner;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Configuration\InvalidSettings;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\LocalSigningKey;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The remote signing backends as the composition root builds them: from settings alone,
 * refusing at boot what could only fail later, and — through a custom backend, a key the
 * server never holds — issuing tokens a relying party verifies with the published JWKS.
 */
final class RemoteSigningTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use OidcFixtures;

    private const string CUSTOM = LocalSigningKey::class;

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function cloudKeys(): iterable
    {
        yield 'AWS KMS' => ['aws-kms', 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'];
        yield 'Google Cloud KMS' => [
            'gcp-kms',
            'projects/p/locations/europe-west1/keyRings/clavia/cryptoKeys/signing/cryptoKeyVersions/1',
        ];
        yield 'Azure Key Vault' => [
            'azure-key-vault',
            'https://clavia.vault.azure.net/keys/signing/0123456789abcdef0123456789abcdef',
        ];
    }

    #[DataProvider('cloudKeys')]
    public function testACloudBackendIsBuiltWithoutCallingItsProvider(string $backend, string $reference): void
    {
        // No credentials and no network here: building must not need either, or a server
        // whose provider is briefly unreachable could not start.
        $this->boot(['CLAVIA_SIGNING_BACKEND' => $backend, 'CLAVIA_SIGNING_KEY_REF' => $reference]);

        self::assertInstanceOf(RemoteTokenSigner::class, $this->container()->get(TokenSigner::class));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function mutableReferences(): iterable
    {
        yield 'an AWS alias' => ['aws-kms', 'alias/clavia', 'an alias can be repointed'];
        yield 'a Cloud KMS key without its version' => [
            'gcp-kms',
            'projects/p/locations/l/keyRings/r/cryptoKeys/signing',
            'cryptoKeyVersions/N',
        ];
        yield 'a Key Vault key without its version' => [
            'azure-key-vault',
            'https://clavia.vault.azure.net/keys/signing',
            'versioned URL',
        ];
    }

    #[DataProvider('mutableReferences')]
    public function testAReferenceThatCouldNameAnotherKeyTomorrowIsRefusedAtBoot(
        string $backend,
        string $reference,
        string $why,
    ): void {
        $this->boot(['CLAVIA_SIGNING_BACKEND' => $backend, 'CLAVIA_SIGNING_KEY_REF' => $reference]);

        self::assertStringContainsString($why, $this->refusalOf(TokenSigner::class));
    }

    public function testARetiredKeyIsCheckedLikeTheActiveOne(): void
    {
        $this->boot([
            'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
            'CLAVIA_SIGNING_KEY_REF' => 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
            'CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'alias/old',
        ]);

        self::assertStringContainsString('an alias can be repointed', $this->refusalOf(TokenSigner::class));
    }

    public function testAKeyIdWithoutARegionIsRefusedAtBoot(): void
    {
        $previous = getenv('AWS_REGION');
        putenv('AWS_REGION');
        try {
            $this->boot([
                'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
                'CLAVIA_SIGNING_KEY_REF' => '1234abcd-12ab-34cd-56ef-1234567890ab',
            ]);

            self::assertStringContainsString('needs CLAVIA_AWS_REGION', $this->refusalOf(TokenSigner::class));

            $this->boot([
                'CLAVIA_SIGNING_BACKEND' => 'aws-kms',
                'CLAVIA_SIGNING_KEY_REF' => '1234abcd-12ab-34cd-56ef-1234567890ab',
                'CLAVIA_AWS_REGION' => 'eu-west-3',
            ]);
            self::assertInstanceOf(RemoteTokenSigner::class, $this->container()->get(TokenSigner::class));
        } finally {
            putenv($previous === false ? 'AWS_REGION' : 'AWS_REGION=' . $previous);
        }
    }

    public function testANameThatIsNeitherABackendNorAKeyClassIsRefused(): void
    {
        foreach (['not-a-backend', 'stdClass'] as $backend) {
            $this->boot(['CLAVIA_SIGNING_BACKEND' => $backend, 'CLAVIA_SIGNING_KEY_REF' => 'x']);

            self::assertStringContainsString(
                "CLAVIA_SIGNING_BACKEND='{$backend}' is neither a built-in backend (postgres, aws-kms, gcp-kms, "
                . 'azure-key-vault) nor a class implementing',
                $this->refusalOf(TokenSigner::class),
            );
        }
    }

    public function testACustomBackendIsBuiltFromItsReferenceAndItsOwnRefusalsAreReported(): void
    {
        $this->boot(['CLAVIA_SIGNING_BACKEND' => self::CUSTOM, 'CLAVIA_SIGNING_KEY_REF' => 'elsewhere']);

        self::assertSame("A local key is 'local:<n>', not 'elsewhere'.", $this->refusalOf(TokenSigner::class));
    }

    public function testTokensSignedByAKeyTheServerNeverHoldsVerifyAgainstItsJwks(): void
    {
        $this->bootCustom();
        $this->user();
        $this->publicClient();

        $published = self::json($this->get('/oidc/jwks.json'));
        $tokens = $this->completeFlow('openid');
        $idToken = $this->verifiedIdToken($tokens['id_token'] ?? null);

        /** @var array{keys: list<array{kid: string}>} $published */
        self::assertSame(
            [new LocalHsm(5)->kid(), new LocalHsm(6)->kid()],
            array_column($published['keys'], 'kid'),
            'The active key, then the retired one.',
        );
        self::assertSame(new LocalHsm(5)->kid(), $idToken['header']['kid'] ?? null);
    }

    public function testKeysTheProviderHoldsAreNotManagedHere(): void
    {
        $this->bootCustom();

        self::assertStringContainsString(
            'keeps its keys at the provider: create and rotate them there',
            $this->refusalOf(SigningKeyStore::class),
        );
    }

    public function testSeedingADevelopmentSetupLeavesTheProvidersKeysAlone(): void
    {
        $this->bootCustom();

        /** @var SeedDevelopmentData $seed */
        $seed = $this->container()->get(SeedDevelopmentData::class);
        $seeded = $seed('dev@example.test', 'correct horse battery', 'https://app.test/callback');

        self::assertNull($seeded->signingKeyId);
        self::assertFalse($seeded->signingKeyCreated);
    }

    private function bootCustom(): void
    {
        $this->boot([
            'CLAVIA_SIGNING_BACKEND' => self::CUSTOM,
            'CLAVIA_SIGNING_KEY_REF' => 'local:5',
            'CLAVIA_SIGNING_RETIRED_KEY_REFS' => 'local:6',
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
        ]);
    }

    /** What the container said when it refused to build `$service`. */
    private function refusalOf(string $service): string
    {
        try {
            $this->container()->get($service);
        } catch (ServiceNotCreatedException $refusal) {
            $cause = $refusal->getPrevious();
            self::assertInstanceOf(InvalidSettings::class, $cause);

            return $cause->getMessage();
        }

        self::fail(sprintf('%s was built.', $service));
    }
}
