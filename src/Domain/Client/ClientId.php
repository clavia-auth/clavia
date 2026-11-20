<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The public identifier a client application presents — and its primary key.
 *
 * Generated, not chosen, and immutable: "changing" a client id is registering a new
 * client. It is not a secret: it travels in every authorization request, in browser
 * history and in logs.
 */
final readonly class ClientId
{
    public const int MAX_LENGTH = 64;

    /**
     * @param non-empty-string $value
     */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value could not be the identifier of any client.
     */
    public static function fromString(string $value): self
    {
        // Visible ASCII only (RFC 6749 Appendix A.1), and no colon: a client id holding one
        // could not be told from its secret in HTTP Basic credentials (RFC 7617 §2).
        $isVisibleAsciiWithoutColon = preg_match('/^[\x21-\x39\x3B-\x7E]+$/D', $value) === 1;
        if ($value === '' || strlen($value) > self::MAX_LENGTH || ! $isVisibleAsciiWithoutColon) {
            throw new InvalidValue('A client id is 1 to 64 visible ASCII characters, with no space and no colon.');
        }

        return new self($value);
    }

    /** A fresh identifier: 32 letters and digits, as unguessable as it is unmemorable. */
    public static function generate(SecretGenerator $secrets): self
    {
        return new self($secrets->alphanumeric(32));
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
