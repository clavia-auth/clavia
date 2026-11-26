<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GcpKmsKey;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Google Cloud KMS's REST API for one key version, answering from a {@see LocalHsm} as the
 * service does: a SHA-256 digest only, its CRC32C verified, checksums on what it returns.
 * Wrong ones can be ordered, to see them caught.
 */
final class FakeCloudKms
{
    public string $algorithm = 'RSA_SIGN_PKCS1_2048_SHA256';

    public bool $corruptSignature = false;

    public bool $confirmDigest = true;

    public function __construct(
        public readonly string $keyVersion,
        private readonly LocalHsm $hsm = new LocalHsm(),
        private readonly string $token = 'google-token',
    ) {
    }

    public function __invoke(RequestInterface $request): ResponseInterface
    {
        if ($request->getHeaderLine('Authorization') !== 'Bearer ' . $this->token) {
            return new JsonResponse(
                [
                    'error' => [
                        'code' => StatusCodeInterface::STATUS_UNAUTHORIZED,
                        'message' => 'Request had invalid credentials.',
                    ],
                ],
                StatusCodeInterface::STATUS_UNAUTHORIZED,
            );
        }

        return match ([$request->getMethod(), (string) $request->getUri()]) {
            [
                RequestMethodInterface::METHOD_POST,
                GcpKmsKey::API . $this->keyVersion . ':asymmetricSign',
            ] => $this->sign($request),
            [
                RequestMethodInterface::METHOD_POST,
                GcpKmsKey::API . $this->keyVersion . ':asymmetricDecrypt',
            ] => $this->decrypt($request),
            [
                RequestMethodInterface::METHOD_GET,
                GcpKmsKey::API . $this->keyVersion . '/publicKey',
            ] => new JsonResponse([
                'pem' => $this->hsm->publicPem(),
                'algorithm' => $this->algorithm,
                'pemCrc32c' => self::crc32c($this->hsm->publicPem()),
                'name' => $this->keyVersion,
            ]),
            default => new JsonResponse(
                ['error' => ['code' => StatusCodeInterface::STATUS_NOT_FOUND, 'message' => 'Not found.']],
                StatusCodeInterface::STATUS_NOT_FOUND,
            ),
        };
    }

    /** As Cloud KMS does: with the key version's own OAEP digest, a checksum each way. */
    private function decrypt(RequestInterface $request): ResponseInterface
    {
        /** @var array{ciphertext?: string, ciphertextCrc32c?: string} $body */
        $body = json_decode((string) $request->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $ciphertext = base64_decode($body['ciphertext'] ?? '', true);
        $digest = str_ends_with($this->algorithm, '_SHA1') ? 'sha1' : 'sha256';
        $plaintext = str_starts_with($this->algorithm, 'RSA_DECRYPT_OAEP_') && is_string($ciphertext)
            ? $this->hsm->decrypt($ciphertext, $digest)
            : null;
        if ($plaintext === null) {
            return new JsonResponse(
                ['error' => ['code' => StatusCodeInterface::STATUS_BAD_REQUEST, 'message' => 'Decryption failed.']],
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        return new JsonResponse([
            'plaintext' => base64_encode($plaintext),
            'plaintextCrc32c' => self::crc32c($plaintext),
            'verifiedCiphertextCrc32c' => ($body['ciphertextCrc32c'] ?? null) === self::crc32c((string) $ciphertext),
        ]);
    }

    private function sign(RequestInterface $request): ResponseInterface
    {
        /** @var array{digest: array{sha256?: string}, digestCrc32c?: string} $body */
        $body = json_decode((string) $request->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $digest = base64_decode($body['digest']['sha256'] ?? '', true);
        if ($digest === false || strlen($digest) !== 32) {
            return new JsonResponse(
                [
                    'error' => [
                        'code' => StatusCodeInterface::STATUS_BAD_REQUEST,
                        'message' => 'Digest is not a SHA-256.',
                    ],
                ],
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        $signature = $this->hsm->signDigest($digest);

        return new JsonResponse([
            'signature' => base64_encode($this->corruptSignature ? strrev($signature) : $signature),
            'signatureCrc32c' => self::crc32c($signature),
            'verifiedDigestCrc32c' => $this->confirmDigest && ($body['digestCrc32c'] ?? null) === self::crc32c($digest),
            'name' => $this->keyVersion,
        ]);
    }

    private static function crc32c(string $bytes): string
    {
        return (string) hexdec(hash('crc32c', $bytes));
    }
}
