<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\Aws\AwsKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Contract\RemoteSigningKeyContract;
use ClaviaTest\Support\Fake\FakeKms;
use ClaviaTest\Support\Fake\LocalHsm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AwsKmsKeyTest extends TestCase
{
    use RemoteSigningKeyContract;

    private const string ARN = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

    private FakeKms $kms;

    #[\Override]
    protected function setUp(): void
    {
        $this->kms = new FakeKms();
    }

    #[\Override]
    protected function key(): RemoteSigningKey
    {
        return new AwsKmsKey($this->kms->client(), self::ARN);
    }

    #[\Override]
    protected function hsm(): LocalHsm
    {
        return new LocalHsm();
    }

    public function testKmsIsHandedTheDigestAndTheAlgorithmByItsOwnName(): void
    {
        $digest = hash('sha256', 'header.payload', true);

        $signature = $this->key()->sign($digest, SigningAlgorithm::RS256);

        self::assertSame(new LocalHsm()->signDigest($digest), $signature);
        $command = $this->kms->commands[0] ?? null;
        self::assertNotNull($command);
        self::assertSame('Sign', $command->getName());
        self::assertSame(self::ARN, $command['KeyId']);
        self::assertSame('DIGEST', $command['MessageType']);
        self::assertSame($digest, $command['Message']);
        self::assertSame('RSASSA_PKCS1_V1_5_SHA_256', $command['SigningAlgorithm']);
    }

    public function testABareKeyIdIsAReferenceToo(): void
    {
        $key = new AwsKmsKey($this->kms->client(), '1234abcd-12ab-34cd-56ef-1234567890ab');

        self::assertSame('1234abcd-12ab-34cd-56ef-1234567890ab', $key->reference());
        self::assertNull(AwsKmsKey::regionOf($key->reference()));
        self::assertSame('eu-west-1', AwsKmsKey::regionOf(self::ARN));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableReferences(): iterable
    {
        yield 'an alias' => ['alias/clavia-signing'];
        yield "an alias's ARN" => ['arn:aws:kms:eu-west-1:111122223333:alias/clavia-signing'];
        yield 'another service' => ['arn:aws:iam::111122223333:role/clavia'];
        yield 'nothing like it' => ['my key'];
    }

    #[DataProvider('unusableReferences')]
    public function testAnythingButAKeyArnOrIdIsRefused(string $reference): void
    {
        $this->expectException(InvalidKeyReference::class);

        new AwsKmsKey($this->kms->client(), $reference);
    }

    public function testAnAliasIsRefusedForWhatItCanDo(): void
    {
        $this->expectExceptionMessage('an alias can be repointed at another key');

        new AwsKmsKey($this->kms->client(), 'alias/clavia-signing');
    }

    public function testARefusalIsASigningFailureNamingWhatKmsSaid(): void
    {
        $this->kms->refusal = 'User is not authorized to perform: kms:Sign';

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('AWS KMS refused: User is not authorized to perform: kms:Sign');

        $_ = $this->key()->sign(hash('sha256', 'x', true), SigningAlgorithm::RS256);
    }

    public function testAKeyThatDoesNotSignIsReportedWhenItsPublicHalfIsRead(): void
    {
        $this->kms->keyUsage = 'ENCRYPT_DECRYPT';

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('is not a SIGN_VERIFY key that signs with RSASSA_PKCS1_V1_5_SHA_256');

        $this->key()->publicKey(SigningAlgorithm::RS256);
    }

    public function testAKeyThatDoesNotOfferTheAlgorithmIsReported(): void
    {
        $this->kms->signingAlgorithms = ['RSASSA_PSS_SHA_256'];

        $this->expectException(SigningFailed::class);

        $this->key()->publicKey(SigningAlgorithm::RS256);
    }
}
