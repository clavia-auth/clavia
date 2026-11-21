<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Application\Port\SigningFailed;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The JSON-over-HTTPS calls the REST-based backends make — Google Cloud KMS, Azure Key
 * Vault, and the token endpoints that let them in — with one way of failing: a
 * {@see SigningFailed} that names the service and repeats what it said.
 *
 * Anything but `200` with a JSON object is a refusal. No retry: a token request is
 * answered quickly or not at all, and the client's own retry is the right place for it.
 */
final readonly class JsonApi
{
    /**
     * @param non-empty-string $service What the service is called in an error message.
     */
    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        private string $service,
    ) {
    }

    /**
     * @param array<string, string> $headers
     *
     * @return array<array-key, mixed>
     *
     * @throws SigningFailed
     */
    public function get(string $url, array $headers = []): array
    {
        return $this->send($this->request('GET', $url, $headers));
    }

    /**
     * @param array<string, mixed>  $body
     * @param array<string, string> $headers
     *
     * @return array<array-key, mixed>
     *
     * @throws SigningFailed
     */
    public function postJson(string $url, array $body, array $headers = []): array
    {
        return $this->send(
            $this->request('POST', $url, $headers)
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streams->createStream(json_encode($body, JSON_THROW_ON_ERROR))),
        );
    }

    /**
     * @param array<string, string> $fields
     * @param array<string, string> $headers
     *
     * @return array<array-key, mixed>
     *
     * @throws SigningFailed
     */
    public function postForm(string $url, #[\SensitiveParameter] array $fields, array $headers = []): array
    {
        return $this->send(
            $this->request('POST', $url, $headers)
                ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withBody($this->streams->createStream(http_build_query($fields, '', '&', PHP_QUERY_RFC3986))),
        );
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(string $method, string $url, array $headers): RequestInterface
    {
        $request = $this->requests->createRequest($method, $url)->withHeader('Accept', 'application/json');
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws SigningFailed
     */
    private function send(RequestInterface $request): array
    {
        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $unreachable) {
            throw new SigningFailed(
                sprintf('%s could not be reached: %s', $this->service, $unreachable->getMessage()),
                previous: $unreachable,
            );
        }

        try {
            /** @var mixed $document */
            $document = json_decode((string) $response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $document = null;
        }

        if ($response->getStatusCode() !== 200) {
            throw new SigningFailed(sprintf(
                '%s refused the request (HTTP %d)%s',
                $this->service,
                $response->getStatusCode(),
                ($said = self::errorIn($document)) === null ? '.' : ': ' . $said,
            ));
        }
        if (! is_array($document) || array_is_list($document)) {
            throw new SigningFailed(sprintf('%s answered with something other than a JSON object.', $this->service));
        }

        return $document;
    }

    /**
     * What a refusal says, in the shapes the services use: Google's and Azure's
     * `{"error": {"message": …}}`, and OAuth 2.0's `error` and `error_description`.
     */
    private static function errorIn(mixed $document): ?string
    {
        if (! is_array($document)) {
            return null;
        }

        /** @var mixed $error */
        $error = $document['error'] ?? null;
        /** @var mixed $message */
        $message = is_array($error) ? ($error['message'] ?? null) : ($document['error_description'] ?? $error);

        return is_string($message) && $message !== '' ? $message : null;
    }
}
