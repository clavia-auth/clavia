<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\TestSigningKeys;

/**
 * A custom backend, written as an operator would write one: built from its reference
 * alone (`local:<n>`, test key number n), signing with a key no other code touches.
 *
 * Counts what it is asked, to show what the server keeps from asking twice.
 */
final class LocalSigningKey implements RemoteSigningKey
{
    /** @var array<string, int> Public-key reads, by reference, across instances. */
    public static array $publicKeyReads = [];

    private readonly LocalHsm $hsm;

    /** @var non-empty-string */
    private readonly string $reference;

    public function __construct(string $reference)
    {
        if (preg_match('/^local:([0-9])$/D', $reference, $match) !== 1) {
            throw new InvalidKeyReference(sprintf("A local key is 'local:<n>', not '%s'.", $reference));
        }

        assert($reference !== '');
        $this->hsm = new LocalHsm((int) $match[1]);
        $this->reference = $reference;
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function sign(string $digest, SigningAlgorithm $algorithm): string
    {
        $signature = $this->hsm->signDigest($digest);
        assert($signature !== '');

        return $signature;
    }

    #[\Override]
    public function publicKey(SigningAlgorithm $algorithm): PublicJwk
    {
        self::$publicKeyReads[$this->reference] = (self::$publicKeyReads[$this->reference] ?? 0) + 1;

        return TestSigningKeys::publicJwk((int) substr($this->reference, 6), $algorithm);
    }
}
