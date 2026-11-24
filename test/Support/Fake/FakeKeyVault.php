<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\Remote\Azure\AzureKeyVaultKey;
use Clavia\Domain\Shared\Base64Url;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Azure Key Vault's REST API for one versioned key, answering from a {@see LocalHsm} as the
 * service does: `RS256` over a digest, values in base64url, the key's components raw.
 */
final class FakeKeyVault
{
    public string $keyType = 'RSA-HSM';

    /** @var list<string> */
    public array $operations = ['sign', 'verify'];

    public bool $enabled = true;

    public ?string $answeringKid = null;

    public function __construct(
        public readonly string $keyUrl,
        private readonly LocalHsm $hsm = new LocalHsm(),
        private readonly string $token = 'azure-token',
    ) {
    }

    public function __invoke(RequestInterface $request): ResponseInterface
    {
        if ($request->getHeaderLine('Authorization') !== 'Bearer ' . $this->token) {
            return new JsonResponse(
                ['error' => ['code' => 'Unauthorized', 'message' => 'AKV10000: no token.']],
                StatusCodeInterface::STATUS_UNAUTHORIZED,
            );
        }
        if ($request->getUri()->getQuery() !== 'api-version=' . AzureKeyVaultKey::API_VERSION) {
            return new JsonResponse(
                ['error' => ['code' => 'BadParameter', 'message' => 'api-version.']],
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        $kid = $this->answeringKid ?? $this->keyUrl;
        $numbers = $this->hsm->numbers();

        return match ([$request->getMethod(), (string) $request->getUri()->withQuery('')]) {
            ['POST', $this->keyUrl . '/sign'] => $this->sign($request, $kid),
            ['GET', $this->keyUrl] => new JsonResponse([
                'key' => [
                    'kid' => $kid,
                    'kty' => $this->keyType,
                    'key_ops' => $this->operations,
                    'n' => Base64Url::encode($numbers['n']),
                    'e' => Base64Url::encode($numbers['e']),
                ],
                'attributes' => ['enabled' => $this->enabled],
            ]),
            default => new JsonResponse(
                ['error' => ['code' => 'KeyNotFound', 'message' => 'No such key.']],
                StatusCodeInterface::STATUS_NOT_FOUND,
            ),
        };
    }

    private function sign(RequestInterface $request, string $kid): ResponseInterface
    {
        /** @var array{alg?: string, value?: string} $body */
        $body = json_decode((string) $request->getBody(), true, flags: JSON_THROW_ON_ERROR);
        if (($body['alg'] ?? null) !== 'RS256') {
            return new JsonResponse(
                ['error' => ['code' => 'BadParameter', 'message' => 'Unknown alg.']],
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        return new JsonResponse([
            'kid' => $kid,
            'value' => Base64Url::encode($this->hsm->signDigest(Base64Url::decode($body['value'] ?? ''))),
        ]);
    }
}
