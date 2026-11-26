<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Fig\Http\Message\RequestMethodInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Psr\Http\Message\ResponseInterface;

use const CURLOPT_CONNECT_TO;

/**
 * A browser, as far as these suites need one: a cookie jar that keeps to the rules of the cookies it
 * is given (host, path, `Secure`), redirects followed one hop at a time so each response can be looked
 * at, and the TLS of the stack trusted through its CA and nothing else.
 */
final class Browser
{
    private readonly Client $client;
    private readonly CookieJar $cookies;
    private ?ResponseInterface $last = null;
    private string $lastUrl = '';

    public function __construct(private readonly Stack $stack)
    {
        $this->cookies = new CookieJar();
        $connectTo = [];
        foreach (['auth', 'management'] as $host) {
            $connectTo[] = sprintf('%s.%s:443:%s:%d', $host, Stack::DOMAIN, $stack->address, $stack->httpsPort);
        }
        $this->client = new Client([
            'allow_redirects' => false,
            'http_errors' => false,
            'cookies' => $this->cookies,
            'verify' => $stack->certificateAuthority,
            'timeout' => 20,
            'curl' => [CURLOPT_CONNECT_TO => $connectTo],
        ]);
    }

    /** @param array<string, mixed> $options Guzzle's, plus nothing of ours. */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $this->lastUrl = $this->ofTheStack($url);

        return $this->last = $this->client->request($method, $this->lastUrl, $options);
    }

    public function last(): ResponseInterface
    {
        return $this->last ?? throw new \LogicException('No request has been made.');
    }

    /** Follow redirects until a response is not one, or its target satisfies `$stop` (and is not requested). */
    public function follow(callable $stop, int $limit = 10): ResponseInterface
    {
        $response = $this->last();
        for ($hops = 0; $hops < $limit && $this->isRedirect($response); ++$hops) {
            $target = $this->absolute($response->getHeaderLine('Location'));
            if ($stop($target)) {
                break;
            }
            $response = $this->request(RequestMethodInterface::METHOD_GET, $target);
        }

        return $response;
    }

    /** The `Location` of the last response as an absolute URL. */
    public function location(): string
    {
        return $this->absolute($this->last()->getHeaderLine('Location'));
    }

    public function stack(): Stack
    {
        return $this->stack;
    }

    /**
     * The suite follows redirects, so it checks where they lead: the stack's own hosts, over https, and
     * nowhere else.
     *
     * @psalm-taint-escape ssrf
     */
    private function ofTheStack(string $url): string
    {
        $host = (string) parse_url($url, PHP_URL_HOST);
        $hosts = ['auth.' . Stack::DOMAIN, 'management.' . Stack::DOMAIN];
        if (! str_starts_with($url, 'https://') || ! in_array($host, $hosts, true)) {
            throw new \RuntimeException(sprintf('%s is not on the stack.', $url));
        }

        return $url;
    }

    private function isRedirect(ResponseInterface $response): bool
    {
        return $response->getStatusCode() >= 300 && $response->getStatusCode() < 400
            && $response->hasHeader('Location');
    }

    /** A `Location` against the URL that was requested: absolute, or a path on the same origin. */
    private function absolute(string $location): string
    {
        if (preg_match('#^https?://#', $location) === 1) {
            return $location;
        }
        $origin = (string) preg_replace('#^(https?://[^/]+).*$#', '$1', $this->lastUrl);

        return $origin . '/' . ltrim($location, '/');
    }
}
