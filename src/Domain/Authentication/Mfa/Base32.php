<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use Clavia\Domain\Shared\InvalidValue;

/**
 * RFC 4648 §6 base32, the alphabet authenticator apps take a TOTP seed in.
 *
 * Encoded without padding (Key Uri Format), decoded case-insensitively with or without
 * it, and ignoring the spaces people type between groups.
 */
final class Base32
{
    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private function __construct()
    {
    }

    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        $encoded = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0, $length = strlen($bytes); $i < $length; ++$i) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $encoded .= self::ALPHABET[($buffer >> $bits) & 0x1F];
            }
            $buffer &= (1 << $bits) - 1;
        }
        if ($bits > 0) {
            $encoded .= self::ALPHABET[($buffer << (5 - $bits)) & 0x1F];
        }

        return $encoded;
    }

    /**
     * @throws InvalidValue When a character is outside the alphabet, or the length cannot be
     *                      the encoding of whole bytes.
     */
    public static function decode(#[\SensitiveParameter] string $encoded): string
    {
        $normalised = rtrim(strtoupper(str_replace(' ', '', $encoded)), '=');
        if (preg_match('/^[A-Z2-7]*$/D', $normalised) !== 1) {
            throw new InvalidValue('A base32 value holds only the letters A–Z and the digits 2–7.');
        }

        $bytes = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0, $length = strlen($normalised); $i < $length; ++$i) {
            $buffer = ($buffer << 5) | (int) strpos(self::ALPHABET, $normalised[$i]);
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $bytes .= chr(($buffer >> $bits) & 0xFF);
                $buffer &= (1 << $bits) - 1;
            }
        }

        // What is left must be fewer than five bits, all zero: anything else is not the
        // encoding of whole bytes.
        if ($bits >= 5 || $buffer !== 0) {
            throw new InvalidValue('This is not the base32 encoding of whole bytes.');
        }

        return $bytes;
    }
}
