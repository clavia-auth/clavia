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

/**
 * An application's logo on the sign-in pages, kept by this server and served from its own origin: the
 * pages' policy loads no image from anywhere else.
 *
 * A raster image only, PNG, JPEG or WebP, recognised by its content, never by what the caller says it is.
 * Never SVG: an SVG document can carry script, and opened on its own it would run on the sign-in origin.
 * At most {@see self::MAX_BYTES} and {@see self::MAX_SIDE} pixels a side, at least {@see self::MIN_SIDE}.
 */
final readonly class ClientLogo
{
    public const int MAX_BYTES = 256 * 1024;
    public const int MIN_SIDE = 16;
    public const int MAX_SIDE = 1024;

    /** The media types taken, by what PHP recognises the content as. */
    private const array TYPES = [
        IMAGETYPE_PNG => 'image/png',
        IMAGETYPE_JPEG => 'image/jpeg',
        IMAGETYPE_WEBP => 'image/webp',
    ];

    /**
     * @param non-empty-string $mediaType
     * @param non-empty-string $content
     * @param non-empty-string $version   The first sixteen hexadecimal digits of the content's SHA-256: what
     *                                    the pages name it by, so a new logo is a new address.
     */
    private function __construct(
        public ClientId $clientId,
        public string $mediaType,
        public string $content,
        public string $version,
    ) {
    }

    /** @throws InvalidValue For anything but a PNG, JPEG or WebP image within the bounds. */
    public static function fromBytes(ClientId $clientId, string $content): self
    {
        if ($content === '' || strlen($content) > self::MAX_BYTES) {
            throw new InvalidValue('A logo is an image of at most 256 KiB.');
        }
        $size = @getimagesizefromstring($content);
        $type = $size === false ? null : (self::TYPES[$size[2]] ?? null);
        if ($size === false || $type === null) {
            throw new InvalidValue('A logo is a PNG, JPEG or WebP image.');
        }
        foreach ([$size[0], $size[1]] as $side) {
            if ($side < self::MIN_SIDE || $side > self::MAX_SIDE) {
                throw new InvalidValue('A logo is 16 to 1024 pixels a side.');
            }
        }

        return new self($clientId, $type, $content, substr(hash('sha256', $content), 0, 16));
    }

    /**
     * As kept, read back: held to the same rules.
     *
     * @throws InvalidValue
     */
    public static function restore(ClientId $clientId, string $content): self
    {
        return self::fromBytes($clientId, $content);
    }
}
