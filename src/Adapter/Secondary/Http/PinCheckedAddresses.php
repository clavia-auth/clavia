<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Http;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Guzzle middleware: every outbound request passes the {@see OutboundUrlPolicy}, and is
 * then made to the addresses the policy checked — handed to cURL with `CURLOPT_RESOLVE`
 * — rather than to whatever the name resolves to a moment later.
 *
 * Checking a URL and letting the client resolve it again leaves a window: a hostile DNS
 * server answers a public address to the check and `169.254.169.254` to the fetch. With
 * the address pinned, the fetch goes where the check looked. A request the policy refuses
 * is not sent; it fails as one that could not connect.
 *
 * Pinning is cURL's: `ext-curl` is a requirement of the image, and Guzzle picks its cURL
 * handler whenever the extension is loaded.
 */
final readonly class PinCheckedAddresses
{
    public function __construct(private OutboundUrlPolicy $policy)
    {
    }

    /**
     * Guzzle's middleware shape: the next handler in, a handler out.
     */
    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler): PromiseInterface {
            $uri = $request->getUri();
            try {
                $addresses = $this->policy->addresses((string) $uri, 'request URL');
            } catch (OutboundUrlRefused $refused) {
                return Create::rejectionFor(new ConnectException($refused->getMessage(), $request));
            }

            if ($addresses !== []) {
                /** @var array<int, mixed> $curl */
                $curl = is_array($options['curl'] ?? null) ? $options['curl'] : [];
                $curl[CURLOPT_RESOLVE] = [sprintf(
                    '%s:%d:%s',
                    $uri->getHost(),
                    $uri->getPort() ?? 443,
                    implode(',', array_map(self::forCurl(...), $addresses)),
                )];
                $options['curl'] = $curl;
            }

            $promise = $handler($request, $options);
            assert($promise instanceof PromiseInterface);

            return $promise;
        };
    }

    /** An address as `CURLOPT_RESOLVE` takes it: IPv6 in brackets. */
    private static function forCurl(string $address): string
    {
        return str_contains($address, ':') ? '[' . $address . ']' : $address;
    }
}
