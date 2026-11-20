<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\InvalidValue;

/**
 * The PKCE challenge of an authorization request (RFC 7636 §4.2), always `S256`.
 *
 * The client keeps a random `code_verifier` and sends only its SHA-256 here. Whoever
 * later redeems the code must present the verifier, so a code intercepted on its way
 * back to the client is useless to the interceptor.
 *
 * There is no `plain` method in this server: with it the challenge *is* the verifier,
 * and anyone who saw the authorization request could redeem the code.
 */
final readonly class CodeChallenge
{
    /** The only transformation offered (RFC 7636 §4.2). */
    public const string METHOD = 'S256';

    /** BASE64URL-ENCODE(SHA256(verifier)) without padding: always 43 characters. */
    private const string PATTERN = '/^[A-Za-z0-9_-]{43}$/D';

    /**
     * @param non-empty-string $value
     */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value cannot be the S256 transformation of anything.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue('An S256 code challenge is 43 characters of the base64url alphabet.');
        }

        return new self($value);
    }

    /** The challenge a client would send for `$verifier`. */
    public static function forVerifier(CodeVerifier $verifier): self
    {
        $value = rtrim(strtr(base64_encode(hash('sha256', $verifier->value, true)), '+/', '-_'), '=');
        assert($value !== '');

        return new self($value);
    }

    /** Whether `$verifier` is the secret this challenge was derived from. Constant-time. */
    public function isSatisfiedBy(CodeVerifier $verifier): bool
    {
        return hash_equals($this->value, self::forVerifier($verifier)->value);
    }
}
