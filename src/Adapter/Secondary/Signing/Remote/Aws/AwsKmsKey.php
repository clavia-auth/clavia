<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote\Aws;

use Aws\Exception\AwsException;
use Aws\Exception\CredentialsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Adapter\Secondary\Signing\Remote\SubjectPublicKeyInfo;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Closure;

/**
 * A key in AWS KMS (`CLAVIA_SIGNING_BACKEND=aws-kms`): generated in the HSM, it never leaves
 * it, and this process only calls `Sign` and `GetPublicKey` — the two permissions the role
 * needs.
 *
 * Create it with `KeyUsage=SIGN_VERIFY`, an RSA key spec, and `Origin=AWS_KMS`: imported
 * material existed outside the HSM once. Name it by its key ARN or key id; an alias is
 * refused, because repointing it would change the key under every token already issued.
 *
 * `Sign` is called with `MessageType=DIGEST`: KMS signs the SHA-256 this server computed,
 * as every other backend does, instead of hashing a message itself — which it would only
 * do for messages up to 4 KB.
 *
 * Requires `aws/aws-sdk-php`.
 */
final readonly class AwsKmsKey implements RemoteSigningKey
{
    private const string KEY_ARN = '/^arn:aws[a-z-]*:kms:(?<region>[a-z0-9-]+):[0-9]{12}:key\/[A-Za-z0-9-]+$/D';

    private const string KEY_ID = '/^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/D';

    /** @var non-empty-string */
    private string $reference;

    /**
     * @throws InvalidKeyReference When `$reference` is neither a key ARN nor a key id.
     */
    public function __construct(private KmsClient $client, string $reference)
    {
        $this->reference = self::checked($reference);
    }

    /**
     * `$reference`, if it names one key for good: its key ARN or key id.
     *
     * @return non-empty-string
     *
     * @throws InvalidKeyReference
     */
    public static function checked(string $reference): string
    {
        if (preg_match(self::KEY_ARN, $reference) !== 1 && preg_match(self::KEY_ID, $reference) !== 1) {
            throw new InvalidKeyReference(sprintf(
                'An AWS KMS signing key is named by its key ARN or key id, not %s%s.',
                var_export($reference, true),
                str_contains($reference, 'alias/') ? ': an alias can be repointed at another key' : '',
            ));
        }
        assert($reference !== '');

        return $reference;
    }

    /** The region a key ARN names; null for a bare key id. */
    public static function regionOf(string $reference): ?string
    {
        return preg_match(self::KEY_ARN, $reference, $match) === 1 ? $match['region'] : null;
    }

    /** KMS's name for the primitive a JWS algorithm names. */
    public static function algorithmName(SigningAlgorithm $algorithm): string
    {
        return match ($algorithm) {
            SigningAlgorithm::RS256 => 'RSASSA_PKCS1_V1_5_SHA_256',
        };
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function sign(string $digest, SigningAlgorithm $algorithm): string
    {
        $result = $this->call(fn (): Result => $this->client->sign([
            'KeyId' => $this->reference,
            'Message' => $digest,
            'MessageType' => 'DIGEST',
            'SigningAlgorithm' => self::algorithmName($algorithm),
        ]));

        /** @var mixed $signature */
        $signature = $result['Signature'] ?? null;
        if (! is_string($signature) || $signature === '') {
            throw new SigningFailed('AWS KMS returned no signature.');
        }

        return $signature;
    }

    #[\Override]
    public function publicKey(SigningAlgorithm $algorithm): PublicJwk
    {
        $result = $this->call(fn (): Result => $this->client->getPublicKey(['KeyId' => $this->reference]));

        /** @var mixed $algorithms */
        $algorithms = $result['SigningAlgorithms'] ?? [];
        if (
            ($result['KeyUsage'] ?? null) !== 'SIGN_VERIFY'
            || ! is_array($algorithms)
            || ! in_array(self::algorithmName($algorithm), $algorithms, true)
        ) {
            throw new SigningFailed(sprintf(
                'The AWS KMS key %s is not a SIGN_VERIFY key that signs with %s.',
                $this->reference,
                self::algorithmName($algorithm),
            ));
        }

        /** @var mixed $publicKey */
        $publicKey = $result['PublicKey'] ?? null;
        if (! is_string($publicKey)) {
            throw new SigningFailed('AWS KMS returned no public key.');
        }

        return SubjectPublicKeyInfo::toJwk($publicKey, $algorithm);
    }

    /**
     * @param Closure(): Result $call
     *
     * @throws SigningFailed
     */
    private function call(Closure $call): Result
    {
        try {
            return $call();
        } catch (AwsException $refused) {
            throw new SigningFailed(
                sprintf('AWS KMS refused: %s', $refused->getAwsErrorMessage() ?? $refused->getMessage()),
                previous: $refused,
            );
        } catch (CredentialsException $unauthenticated) {
            throw new SigningFailed(
                sprintf('No AWS credentials to call KMS with: %s', $unauthenticated->getMessage()),
                previous: $unauthenticated,
            );
        }
    }
}
