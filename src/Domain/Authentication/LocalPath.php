<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use Clavia\Domain\Shared\InvalidValue;

/**
 * A redirect target that cannot leave this server: an absolute path, with its query.
 *
 * An authorization server that bounces people to an arbitrary origin after they sign in
 * is a ready-made phishing endpoint, so nothing that becomes a `Location` is trusted as
 * supplied — not even a value read back from this server's own store. A hostile value
 * is rejected, never repaired: partial repair is far easier to get wrong than refusal.
 *
 * Accepted: a path beginning with exactly one `/`. Refused:
 * - anything with a scheme or an authority (`https://evil.example/`, `javascript:…`);
 * - protocol-relative references (`//evil.example`), which browsers treat as absolute;
 * - backslash variants (`/\evil.example`), which some browsers read as `//`;
 * - any control character, which could split the header it is written into.
 */
final readonly class LocalPath
{
    /** Where a signed-in person lands when nothing valid says otherwise: the login page,
     *  which then says who they are and to go back to the application. */
    public const string DEFAULT = '/auth/login';

    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value could take the browser anywhere but this server.
     */
    public static function fromString(string $value): self
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new InvalidValue('A local path contains no control character.');
        }

        $normalised = str_replace('\\', '/', $value);
        if (! str_starts_with($normalised, '/') || str_starts_with($normalised, '//')) {
            throw new InvalidValue('A local path starts with a single "/".');
        }

        return new self($value);
    }

    /**
     * The candidate when it is a local path, otherwise the fallback.
     */
    public static function orDefault(?string $candidate, string $default = self::DEFAULT): self
    {
        if ($candidate === null || $candidate === '') {
            return self::fromString($default);
        }

        try {
            return self::fromString($candidate);
        } catch (InvalidValue) {
            return self::fromString($default);
        }
    }
}
