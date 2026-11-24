<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use ClaviaTest\Support\TestSigningKeys;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * An OpenID provider on the fake wire: a discovery document, a token endpoint that issues
 * an RS256 ID token, and the JWKS to check it with — the keys being the suite's
 * {@see TestSigningKeys}.
 *
 * What the ID token says is each test's input: {@see $claims} is merged over sensible
 * defaults, a claim set to null is left out, and {@see $nonce} must be set to what the
 * authorization request carried, as a real provider would echo it.
 */
final class FakeOpenIdProvider
{
    public const string ISSUER = 'https://idp.example';
    public const string AUTHORIZATION_ENDPOINT = self::ISSUER . '/authorize';
    public const string TOKEN_ENDPOINT = self::ISSUER . '/token';
    public const string JWKS_URI = self::ISSUER . '/jwks';
    public const string DISCOVERY_URL = self::ISSUER . '/.well-known/openid-configuration';

    /** The nonce to echo: the one the authorization request carried. */
    public ?string $nonce = null;

    /** @var array<string, mixed> Claims merged over the defaults; null removes one. */
    public array $claims = [];

    /** The key the ID token is signed with: an index into {@see TestSigningKeys}. */
    public int $signingKey = 0;

    /** The key whose kid the token names, when not the one it is signed with: a forgery. */
    public ?int $claimedKey = null;

    /** The keys the JWKS publishes. @var list<int> */
    public array $publishedKeys = [0];

    /** @var list<array<string, string>> Every form posted to the token endpoint. */
    public array $tokenRequests = [];

    /** How many times the JWKS was fetched. */
    public int $jwksFetches = 0;

    /** An ID token to answer instead of a minted one; '' answers none at all. */
    public ?string $idTokenOverride = null;

    /** @var array<string, mixed>|null A discovery document to answer instead of the real one. */
    public ?array $discoveryDocument = null;

    public function __construct(public readonly string $clientId = 'clavia-at-idp')
    {
    }

    /** As a {@see FakeHttpClient} handler. */
    public function __invoke(RequestInterface $request): ResponseInterface
    {
        $url = (string) $request->getUri()->withQuery('');

        return match ($url) {
            self::DISCOVERY_URL => new JsonResponse($this->discoveryDocument ?? $this->discovery()),
            self::TOKEN_ENDPOINT => $this->token($request),
            self::JWKS_URI => $this->jwks(),
            default => new JsonResponse(['error' => 'not_found'], StatusCodeInterface::STATUS_NOT_FOUND),
        };
    }

    /** @return array<string, string> */
    public function discovery(): array
    {
        return [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::AUTHORIZATION_ENDPOINT,
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => self::JWKS_URI,
        ];
    }

    /**
     * An ID token carrying the defaults with `$claims` over them, signed with key number
     * `$key` and naming that key's kid.
     *
     * @param array<string, mixed> $claims
     */
    public function idToken(array $claims = [], ?int $key = null): string
    {
        $key ??= $this->signingKey;
        $now = time();
        $payload = array_filter(
            array_merge([
                'iss' => self::ISSUER,
                'aud' => $this->clientId,
                'sub' => 'idp-user-1',
                'email' => 'ada@idp.example',
                'email_verified' => true,
                'iat' => $now,
                'exp' => $now + 300,
                'nonce' => $this->nonce,
            ], $this->claims, $claims),
            static fn (mixed $value): bool => $value !== null,
        );

        $signingInput = self::encode(
            ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => TestSigningKeys::publicJwk($this->claimedKey ?? $key)->kid],
        ) . '.' . self::encode($payload);
        if (! openssl_sign($signingInput, $signature, TestSigningKeys::privateKey($key), OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('OpenSSL could not sign the test ID token.');
        }

        return $signingInput . '.' . self::base64Url($signature);
    }

    private function token(RequestInterface $request): ResponseInterface
    {
        $form = FakeHttpClient::form($request);
        $this->tokenRequests[] = $form;

        $answer = ['access_token' => 'idp-access-token', 'token_type' => 'Bearer', 'expires_in' => 300];
        $idToken = $this->idTokenOverride ?? $this->idToken();
        if ($idToken !== '') {
            $answer['id_token'] = $idToken;
        }

        return new JsonResponse($answer);
    }

    private function jwks(): ResponseInterface
    {
        ++$this->jwksFetches;

        return new JsonResponse(['keys' => array_map(
            static fn (int $index): array => TestSigningKeys::publicJwk($index)->toArray(),
            $this->publishedKeys,
        )]);
    }

    /**
     * A compact JWS from its parts, unsigned unless a signature is given — for tokens no
     * honest provider would issue.
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public static function forged(array $header, array $payload, string $signature = ''): string
    {
        return self::encode($header) . '.' . self::encode($payload) . '.' . self::base64Url($signature);
    }

    /** @param array<string, mixed> $value */
    private static function encode(array $value): string
    {
        return self::base64Url(json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
