<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Application\Port\DecryptionFailed;
use Closure;
use Throwable;

/**
 * This server's encryption keys, as the service provider port may use them to read an encrypted
 * assertion (docs/design/saml-connections.md §5.3): which keys there are (by kid, with the certificate an
 * `EncryptedKey` may name), and the one operation that unwraps a content key through
 * {@see ServiceProviderKeys::decryptKey()}. The port never holds a private key.
 */
final readonly class ContentKeyDecrypter
{
    /**
     * @param list<array{kid: non-empty-string, certificate: non-empty-string}> $keys Next, current and retired;
     *     the certificate DER in base64.
     * @param Closure(non-empty-string, string, OaepDigest): string $decrypt
     */
    public function __construct(public array $keys, private Closure $decrypt)
    {
    }

    /** The content key; null whatever went wrong, one answer for every failure (§7). */
    public function contentKey(string $kid, string $encryptedKey, OaepDigest $digest): ?string
    {
        if ($kid === '') {
            return null;
        }
        try {
            $key = ($this->decrypt)($kid, $encryptedKey, $digest);
        } catch (DecryptionFailed | Throwable) {
            return null;
        }

        return $key === '' ? null : $key;
    }
}
