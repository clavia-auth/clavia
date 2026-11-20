<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\RandomSource;

/**
 * Single-use codes for when the authenticator is gone, issued when a factor is confirmed
 * and stored as digests like every credential that only needs comparing.
 *
 * Three groups of four from an alphabet without look-alikes (no `0`/`o`, `1`/`l`/`i`):
 * a recovery code is read off a printout. About 59 bits each — plenty for something
 * single-use, behind a challenge that is destroyed after a few wrong answers.
 */
final class RecoveryCode
{
    public const string ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    private const int GROUPS = 3;

    private const int GROUP_LENGTH = 4;

    private function __construct()
    {
    }

    /**
     * @param positive-int $count
     *
     * @return list<string> Distinct codes, `xxxx-xxxx-xxxx`.
     */
    public static function issue(RandomSource $random, int $count): array
    {
        $codes = [];
        while (count($codes) < $count) {
            $code = self::generate($random);
            if (! in_array($code, $codes, true)) {
                $codes[] = $code;
            }
        }

        return $codes;
    }

    /**
     * The digest a code is stored and looked up by — of the code however it was typed:
     * case, spaces and dashes do not count.
     */
    public static function digest(#[\SensitiveParameter] string $typed): Digest
    {
        return Digest::of(preg_replace('/[^a-z0-9]/', '', strtolower($typed)) ?? '');
    }

    private static function generate(RandomSource $random): string
    {
        $groups = [];
        for ($group = 0; $group < self::GROUPS; ++$group) {
            $characters = '';
            for ($i = 0; $i < self::GROUP_LENGTH; ++$i) {
                $characters .= self::ALPHABET[$random->integer(0, strlen(self::ALPHABET) - 1)];
            }
            $groups[] = $characters;
        }

        return implode('-', $groups);
    }
}
