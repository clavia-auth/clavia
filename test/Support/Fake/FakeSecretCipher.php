<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\SecretCipher;

/**
 * A cipher that hides nothing, for tests that are not about encryption.
 *
 * It keeps the two properties callers depend on: a ciphertext only opens under the
 * context it was sealed with, and two encryptions of one plaintext differ.
 */
final class FakeSecretCipher implements SecretCipher
{
    private int $counter = 0;

    public bool $available = true;

    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $plaintext, string $context): string
    {
        $this->guard();

        $nonce = (string) ++$this->counter;

        return base64_encode(json_encode(
            ['n' => $nonce, 'p' => base64_encode($plaintext), 'm' => $this->mac($nonce, $plaintext, $context)],
            JSON_THROW_ON_ERROR,
        ));
    }

    #[\Override]
    public function decrypt(string $ciphertext, string $context): string
    {
        $this->guard();

        $decoded = base64_decode($ciphertext, true);
        /** @var mixed $sealed */
        $sealed = $decoded === false ? null : json_decode($decoded, true);

        $nonce = is_array($sealed) ? ($sealed['n'] ?? null) : null;
        $encoded = is_array($sealed) ? ($sealed['p'] ?? null) : null;
        $mac = is_array($sealed) ? ($sealed['m'] ?? null) : null;
        if (! is_string($nonce) || ! is_string($encoded) || ! is_string($mac)) {
            throw new DecryptionFailed('not a ciphertext');
        }

        $plaintext = (string) base64_decode($encoded, true);
        if (! hash_equals($this->mac($nonce, $plaintext, $context), $mac)) {
            throw new DecryptionFailed('authentication failed');
        }

        return $plaintext;
    }

    private function mac(string $nonce, string $plaintext, string $context): string
    {
        return hash('sha256', $nonce . "\0" . $plaintext . "\0" . $context);
    }

    private function guard(): void
    {
        if (! $this->available) {
            throw new EncryptionUnavailable('No encryption key is configured.');
        }
    }
}
