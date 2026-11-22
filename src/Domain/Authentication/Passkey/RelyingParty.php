<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\InvalidValue;
use Uri\Rfc3986\Uri;

/**
 * Who a passkey is for: Clavia's sign-in site (WebAuthn Level 3 §5.4.2, §13.4.1).
 *
 * The **id** is a domain, by default the sign-in host (`auth.example.com`); a passkey works
 * only for that id and its subdomains, which is the whole of what makes it phishing-resistant.
 * The **origin** is the exact address the browser reports for the page, scheme and port
 * included (`https://auth.example.com`), matched byte for byte at every ceremony. The **name**
 * is what an authenticator shows its owner.
 *
 * The origin must belong to the id, or no browser would accept the pair and every ceremony
 * would fail: it is refused here, at startup, rather than at the first sign-in.
 */
final readonly class RelyingParty
{
    private const string LABEL = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?';

    private const string HOST = '/^(?=.{1,253}$)' . self::LABEL . '(\\.' . self::LABEL . ')*$/D';

    /**
     * @param non-empty-string $id
     * @param non-empty-string $name
     * @param non-empty-string $origin
     */
    private function __construct(
        public string $id,
        public string $name,
        public string $origin,
    ) {
    }

    /**
     * @throws InvalidValue When the id is not a lower-case host name, the origin is not an
     *                      `https` origin (a host and an optional port, nothing more) within
     *                      the id, or the name is empty or longer than 64 characters.
     */
    public static function of(string $id, string $name, string $origin): self
    {
        if ($id === '' || preg_match(self::HOST, $id) !== 1) {
            throw new InvalidValue('A relying party id is a lower-case host name.');
        }
        if ($origin === '' || $name === '' || mb_strlen($name) > 64 || preg_match('/[\\p{Cc}\\p{Cf}]/u', $name) === 1) {
            throw new InvalidValue('A relying party name is one to 64 printable characters.');
        }

        $uri = Uri::parse($origin);
        $host = $uri?->getHost();
        $port = $uri?->getPort();
        if (
            $uri === null
            || $uri->getScheme() !== 'https'
            || $host === null
            || $uri->getUserInfo() !== null
            || ($uri->getPath() !== '' && $uri->getPath() !== '/')
            || $uri->getQuery() !== null
            || $uri->getFragment() !== null
            || $origin !== 'https://' . $host . ($port === null ? '' : ':' . $port)
        ) {
            throw new InvalidValue('A relying party origin is an https origin: a host and an optional port.');
        }
        if ($host !== $id && ! str_ends_with($host, '.' . $id)) {
            throw new InvalidValue('The origin must be the relying party id or a subdomain of it.');
        }

        return new self($id, $name, $origin);
    }
}
