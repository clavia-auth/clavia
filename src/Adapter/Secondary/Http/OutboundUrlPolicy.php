<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Http;

use Closure;

/**
 * Which URLs this server may fetch on an operator's say-so.
 *
 * Registering an OpenID Connect connection makes the server fetch the issuer's discovery
 * document, then the token endpoint and the JWKS that document names — a classic way to
 * turn an admin form into a request forger against the network the server sits in: cloud
 * metadata services, internal admin ports, the database. So every such URL must be
 * `https`, and must not point at this host, a private, loopback, link-local or reserved
 * address — written as an IP literal or resolved from a name — nor at a name that is
 * internal by convention (`localhost`, `*.localhost`, `*.internal`).
 *
 * A name that does not resolve is not refused here: the fetch fails on its own. A name
 * that does is fetched at the addresses that were checked, and only those
 * ({@see PinCheckedAddresses}).
 * `CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` (development only) waives the address check,
 * never the scheme.
 */
final readonly class OutboundUrlPolicy
{
    /** @var Closure(string): list<string> */
    private Closure $resolve;

    /**
     * @param bool                               $allowPrivateAddresses `CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES`.
     * @param (callable(string): list<string>)|null $resolve            A host's addresses; DNS by default.
     */
    public function __construct(
        private bool $allowPrivateAddresses,
        ?callable $resolve = null,
    ) {
        $this->resolve = $resolve === null ? self::dns(...) : $resolve(...);
    }

    /**
     * @param string $what What the URL is, for the message: "issuer", "jwks_uri".
     *
     * @throws OutboundUrlRefused
     */
    public function check(string $url, string $what): void
    {
        $this->addresses($url, $what);
    }

    /**
     * Check the URL and say which addresses its host was found at — every one of them
     * public — so that the request can be made to those and no others: a name resolved
     * again by the HTTP client could answer differently the second time (DNS
     * rebinding), and the check would have been for nothing.
     *
     * Empty when there is nothing to pin: the host is an IP literal, the name does not
     * resolve (the request fails on its own), or development waived the address check.
     *
     * @param string $what What the URL is, for the message.
     *
     * @return list<string>
     *
     * @throws OutboundUrlRefused
     */
    public function addresses(string $url, string $what): array
    {
        $parts = parse_url($url);
        $scheme = is_array($parts) ? ($parts['scheme'] ?? null) : null;
        $host = is_array($parts) ? ($parts['host'] ?? null) : null;
        if ($scheme !== 'https' || ! is_string($host) || $host === '') {
            throw new OutboundUrlRefused(sprintf('The %s must be an https URL.', $what));
        }
        if ($this->allowPrivateAddresses) {
            return [];
        }

        $host = strtolower(trim($host, '[]'));
        $refused = new OutboundUrlRefused(sprintf('The %s must not point at this server or an internal host.', $what));
        if (
            $host === 'localhost'
            || str_ends_with($host, '.localhost')
            || str_ends_with($host, '.internal')
        ) {
            throw $refused;
        }

        $literal = filter_var($host, FILTER_VALIDATE_IP) !== false;
        $addresses = $literal ? [$host] : ($this->resolve)($host);
        foreach ($addresses as $address) {
            if (! self::isPublic($address)) {
                throw $refused;
            }
        }

        return $literal ? [] : $addresses;
    }

    /** Whether the address is on the public internet: not private, loopback, link-local or reserved. */
    private static function isPublic(string $address): bool
    {
        $public = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        if ($public === false) {
            return false;
        }
        // Carrier-grade NAT (RFC 6598) and IPv6 unique-local / link-local are not covered by
        // every PHP version's flags; refused explicitly.
        $packed = inet_pton($address);
        if ($packed === false) {
            return false;
        }
        if (strlen($packed) === 4) {
            return ! ((ord($packed[0]) === 100) && (ord($packed[1]) & 0xC0) === 64);
        }

        $first = ord($packed[0]);

        return ($first & 0xFE) !== 0xFC && ! ($first === 0xFE && (ord($packed[1]) & 0xC0) === 0x80);
    }

    /**
     * @return list<string>
     */
    private static function dns(string $host): array
    {
        $addresses = [];
        $v4 = gethostbynamel($host);
        if (is_array($v4)) {
            $addresses = $v4;
        }
        $v6 = @dns_get_record($host, DNS_AAAA);
        if (is_array($v6)) {
            foreach ($v6 as $record) {
                if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                    $addresses[] = $record['ipv6'];
                }
            }
        }

        return $addresses;
    }
}
