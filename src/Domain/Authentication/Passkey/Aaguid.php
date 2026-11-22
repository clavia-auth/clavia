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

/**
 * The make of an authenticator, which a credential manager reports even without attestation
 * (WebAuthn Level 3 §6.5.1): a UUID, used only to label a passkey for its owner and never
 * to refuse one.
 *
 * An authenticator that does not say sends sixteen zero bytes, and that is no value at all:
 * {@see self::fromBytes()} answers null.
 */
final readonly class Aaguid
{
    private const string PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';

    private const string NONE = '00000000-0000-0000-0000-000000000000';

    private function __construct(public string $value)
    {
    }

    /** @throws InvalidValue When it is not a lower-case, hyphenated UUID, or is all zeros. */
    public static function fromString(string $value): self
    {
        if (preg_match(self::PATTERN, $value) !== 1 || $value === self::NONE) {
            throw new InvalidValue('An AAGUID is a lower-case UUID other than all zeros.');
        }

        return new self($value);
    }

    /**
     * From the sixteen bytes of authenticator data; null for all zeros.
     *
     * @throws InvalidValue When it is not sixteen bytes.
     */
    public static function fromBytes(string $bytes): ?self
    {
        if (strlen($bytes) !== 16) {
            throw new InvalidValue('An AAGUID is sixteen bytes.');
        }
        $uuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));

        return $uuid === self::NONE ? null : new self($uuid);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
