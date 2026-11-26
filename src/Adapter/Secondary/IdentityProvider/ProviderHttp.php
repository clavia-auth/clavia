<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Application\Port\IdentityProviderFailed;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * The HTTP an identity provider adapter needs — a form POST to the token endpoint and
 * a GET to an API, both answering JSON — over any PSR-18 client.
 *
 * Every way of not getting a usable answer (transport error, a status outside 2xx, a
 * body that is not JSON) is logged here with the provider and the reason, then thrown
 * as one {@see IdentityProviderFailed}: the person is told the sign-in did not complete,
 * an operator reads why. Response bodies are never logged — they may carry tokens.
 */
final readonly class ProviderHttp
{
    /** GitHub's API refuses requests without one (it names the caller to the provider's operators). */
    public const string USER_AGENT = 'Clavia';

    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * POST `application/x-www-form-urlencoded`, asking for JSON (GitHub answers form-encoded
     * otherwise).
     *
     * @param array<string, string> $form
     *
     * @return array<array-key, mixed> The decoded JSON object or array.
     *
     * @throws IdentityProviderFailed
     */
    public function postForm(string $provider, string $url, array $form): array
    {
        $request = $this->requests->createRequest(RequestMethodInterface::METHOD_POST, $url)
            ->withHeader('User-Agent', self::USER_AGENT)
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streams->createStream(http_build_query($form, '', '&', PHP_QUERY_RFC1738)));

        return $this->send($provider, $request);
    }

    /**
     * A plain GET of a public JSON document: a provider's JWKS.
     *
     * @return array<array-key, mixed> The decoded JSON object or array.
     *
     * @throws IdentityProviderFailed
     */
    public function get(string $provider, string $url): array
    {
        $request = $this->requests->createRequest(RequestMethodInterface::METHOD_GET, $url)
            ->withHeader('User-Agent', self::USER_AGENT)
            ->withHeader('Accept', 'application/json');

        return $this->send($provider, $request);
    }

    /**
     * GET with a bearer token (RFC 6750 §2.1).
     *
     * @return array<array-key, mixed> The decoded JSON object or array.
     *
     * @throws IdentityProviderFailed
     */
    public function getWithToken(
        string $provider,
        string $url,
        #[\SensitiveParameter] string $accessToken,
        string $accept = 'application/json',
    ): array {
        $request = $this->requests->createRequest(RequestMethodInterface::METHOD_GET, $url)
            ->withHeader('User-Agent', self::USER_AGENT)
            ->withHeader('Accept', $accept)
            ->withHeader('Authorization', 'Bearer ' . $accessToken);

        return $this->send($provider, $request);
    }

    /**
     * Log why a provider's answer cannot be used, and throw.
     *
     * @throws IdentityProviderFailed
     */
    public function fail(string $provider, string $reason): never
    {
        $this->logger->warning('External sign-in with {provider} failed: {reason}', [
            'provider' => $provider,
            'reason' => $reason,
        ]);

        throw new IdentityProviderFailed(sprintf('%s: %s', $provider, $reason));
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws IdentityProviderFailed
     */
    private function send(string $provider, RequestInterface $request): array
    {
        $endpoint = $request->getMethod() . ' ' . $request->getUri()->withQuery('')->__toString();

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $failure) {
            $this->fail($provider, sprintf('%s could not be reached (%s).', $endpoint, $failure::class));
        }

        $status = $response->getStatusCode();
        if ($status < StatusCodeInterface::STATUS_OK || $status >= StatusCodeInterface::STATUS_MULTIPLE_CHOICES) {
            $this->fail($provider, sprintf('%s answered %d.', $endpoint, $status));
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode((string) $response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $this->fail($provider, sprintf('%s did not answer JSON.', $endpoint));
        }
        if (! is_array($decoded)) {
            $this->fail($provider, sprintf('%s did not answer a JSON object or array.', $endpoint));
        }

        return $decoded;
    }
}
