<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use ArrayObject;
use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GoogleCredentials;
use Clavia\Adapter\Secondary\Signing\Remote\IssuedToken;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\SubjectPublicKeyInfo;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\TestSigningKeys;
use DomainException;
use Fig\Http\Message\StatusCodeInterface;
use Google\Auth\FetchAuthTokenInterface;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * What the remote backends share: reading a provider's public key, calling its API, and
 * keeping the tokens that call takes.
 */
final class RemoteSigningSupportTest extends TestCase
{
    public function testAPublicKeyReadsTheSameFromDerAndFromPem(): void
    {
        $hsm = new LocalHsm();

        foreach ([$hsm->publicDer(), $hsm->publicPem()] as $encoded) {
            $read = SubjectPublicKeyInfo::toJwk($encoded, SigningAlgorithm::RS256);
            self::assertEquals(TestSigningKeys::publicJwk(), $read);
        }
    }

    public function testOnlyAnRsaKeyOfAtLeast2048BitsIsAccepted(): void
    {
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $short = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024]);
        self::assertNotFalse($ec);
        self::assertNotFalse($short);

        foreach ([$ec, $short] as $key) {
            /** @var array{key: string} $details */
            $details = openssl_pkey_get_details($key);
            try {
                SubjectPublicKeyInfo::toJwk($details['key'], SigningAlgorithm::RS256);
                self::fail('An unusable key was accepted.');
            } catch (SigningFailed $refused) {
                self::assertStringContainsString('RSA key of at least 2048 bits', $refused->getMessage());
            }
        }

        $this->expectException(SigningFailed::class);
        SubjectPublicKeyInfo::toJwk('not a key', SigningAlgorithm::RS256);
    }

    public function testAnApiRefusalRepeatsWhatTheServiceSaid(): void
    {
        $answers = [
            [
                new JsonResponse(
                    ['error' => ['code' => StatusCodeInterface::STATUS_FORBIDDEN, 'message' => 'Denied.']],
                    StatusCodeInterface::STATUS_FORBIDDEN,
                ),
                ': Denied.',
            ],
            [
                new JsonResponse(
                    ['error' => 'invalid_scope', 'error_description' => 'Bad scope.'],
                    StatusCodeInterface::STATUS_BAD_REQUEST,
                ),
                ': Bad scope.',
            ],
            [
                new JsonResponse(['error' => 'invalid_request'], StatusCodeInterface::STATUS_BAD_REQUEST),
                ': invalid_request',
            ],
            [new TextResponse('<html>gateway</html>', StatusCodeInterface::STATUS_BAD_GATEWAY), '(HTTP 502).'],
        ];

        foreach ($answers as [$response, $said]) {
            try {
                $http = new FakeHttpClient(static fn (): JsonResponse|TextResponse => $response);
                self::api($http)->get('https://kms.test/k');
                self::fail('A refusal was taken for an answer.');
            } catch (SigningFailed $refused) {
                self::assertStringStartsWith('The service refused the request', $refused->getMessage());
                self::assertStringEndsWith($said, $refused->getMessage());
            }
        }
    }

    public function testAnApiAnswerIsAJsonObjectOrNothing(): void
    {
        $http = new FakeHttpClient(static fn (): JsonResponse => new JsonResponse(['a', 'list']));

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('answered with something other than a JSON object');

        self::api($http)->get('https://kms.test/k');
    }

    public function testAnUnreachableServiceIsASigningFailure(): void
    {
        $http = new FakeHttpClient(
            static fn (RequestInterface $request): never => throw new ConnectException('timed out', $request),
        );

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('The service could not be reached: timed out');

        self::api($http)->postJson('https://kms.test/k', ['x' => 1]);
    }

    public function testATokenSaysWhenItExpiresOrIsRefused(): void
    {
        $now = new FrozenClock()->now();

        $token = static fn (array $response): IssuedToken => IssuedToken::fromResponse(
            ['access_token' => 't'] + $response,
            $now,
            'S',
        );

        self::assertTrue($token(['expires_in' => 120])->isUsableAt($now));
        self::assertFalse(
            $token(['expires_in' => 60])->isUsableAt($now),
            'Used up to a minute before it expires, not into it.',
        );
        self::assertTrue(
            $token(['expires_on' => (string) ($now->getTimestamp() + 300)])->isUsableAt($now->modify('+239 seconds')),
        );

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('S did not say when its token expires.');
        $token([]);
    }

    public function testGoogleCredentialsAreResolvedAtTheFirstTokenAndKeptUntilItExpires(): void
    {
        $clock = new FrozenClock();
        $resolved = new ArrayObject();
        $credentials = new GoogleCredentials(static function () use ($resolved): FetchAuthTokenInterface {
            $resolved->append(true);

            return self::issuing();
        }, $clock);
        self::assertCount(0, $resolved, 'Nothing is resolved before it is needed.');

        self::assertSame('google-1', $credentials->token());
        self::assertSame('google-1', $credentials->token());
        $clock->advance(3600);
        self::assertSame('google-2', $credentials->token());
        self::assertCount(1, $resolved);
    }

    public function testNoGoogleCredentialsIsASigningFailure(): void
    {
        $credentials = new GoogleCredentials(
            static fn (): never => throw new DomainException('Could not load the default credentials.'),
            new FrozenClock(),
        );

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains(
            'Google Cloud authentication failed: Could not load the default credentials.',
        );

        $_ = $credentials->token();
    }

    private static function api(FakeHttpClient $http): JsonApi
    {
        return new JsonApi($http, new RequestFactory(), new StreamFactory(), 'The service');
    }

    private static function issuing(): FetchAuthTokenInterface
    {
        return new class implements FetchAuthTokenInterface {
            private int $issued = 0;

            /** @return array{access_token: string, expires_in: int} */
            #[\Override]
            public function fetchAuthToken(?callable $httpHandler = null): array
            {
                return ['access_token' => 'google-' . ++$this->issued, 'expires_in' => 3599];
            }

            #[\Override]
            public function getCacheKey(): string
            {
                return 'test-credentials';
            }

            /** @return array{access_token: string}|null */
            #[\Override]
            public function getLastReceivedToken(): ?array
            {
                return null;
            }
        };
    }
}
