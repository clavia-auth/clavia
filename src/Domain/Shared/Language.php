<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * A language a person can read this server's pages and mail in: a BCP 47 tag (RFC 5646) of a primary
 * language subtag and an optional region (`en`, `fr`, `pt-BR`, `es-419`), normalised as BCP 47 writes
 * it (`FR-ca` is `fr-CA`). Scripts, variants and extensions are not kept: no catalogue needs them.
 *
 * Checked by its syntax alone, never by an extension (the domain imports nothing): which languages exist
 * is what the catalogues say ({@see Languages}).
 */
final readonly class Language
{
    private const string TAG = '/^([A-Za-z]{2,3})(?:-([A-Za-z]{2}|[0-9]{3}))?$/D';

    /** @param non-empty-string $tag */
    private function __construct(public string $tag)
    {
    }

    /** @throws InvalidValue When `$tag` is not a language with an optional region. */
    public static function fromString(string $tag): self
    {
        if (preg_match(self::TAG, $tag, $parts) !== 1) {
            throw new InvalidValue('A language is a BCP 47 tag: a language, and an optional region (fr, pt-BR).');
        }
        $normal = strtolower($parts[1]) . (isset($parts[2]) ? '-' . strtoupper($parts[2]) : '');
        assert($normal !== '');

        return new self($normal);
    }

    public function equals(self $other): bool
    {
        return $this->tag === $other->tag;
    }
}
