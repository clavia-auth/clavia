<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use DateTimeImmutable;

/**
 * Time-based one-time passwords: RFC 6238 over RFC 4226 HOTP.
 *
 * Written out rather than taken from a library: the algorithm is a page long, every
 * authenticator app implements exactly this shape (HMAC-SHA-1, six digits, thirty-second
 * steps — the defaults the Key Uri Format assumes), and the decision that matters for
 * security — which time steps a code is accepted for — belongs here, in plain sight.
 */
final class Totp
{
    public const int DIGITS = 6;

    /** Seconds per time step (RFC 6238 §4.1 `X`). */
    public const int PERIOD = 30;

    /**
     * Steps accepted either side of now: one, so a code read a few seconds before the
     * boundary still works (RFC 6238 §5.2). A wider window multiplies a guesser's odds.
     */
    public const int WINDOW = 1;

    public const string ALGORITHM = 'SHA1';

    private function __construct()
    {
    }

    /** The time-step counter at `$instant` (RFC 6238 §4.2, `T0` = the Unix epoch). */
    public static function timeStep(DateTimeImmutable $instant): int
    {
        return intdiv($instant->getTimestamp(), self::PERIOD);
    }

    /** RFC 4226 §5.3: HMAC-SHA-1 of the counter, dynamic truncation, six decimal digits. */
    public static function hotp(TotpSecret $secret, int $counter): string
    {
        $digest = hash_hmac('sha1', pack('J', $counter), $secret->bytes(), true);
        $offset = ord($digest[19]) & 0x0F;
        /** @var array{1: int} $word */
        $word = unpack('N', substr($digest, $offset, 4));

        return str_pad((string) (($word[1] & 0x7FFFFFFF) % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /** The code an app shows at `$instant`. */
    public static function codeAt(TotpSecret $secret, DateTimeImmutable $instant): string
    {
        return self::hotp($secret, self::timeStep($instant));
    }

    /**
     * The time step `$code` is valid for at `$instant`, or null.
     *
     * Checks now and {@see self::WINDOW} steps either side, each comparison in constant
     * time. A step at or before `$lastUsedStep` is refused even when the digits match:
     * that is what makes a code single-use, so six digits read over a shoulder cannot be
     * replayed within their thirty seconds. The caller records the step it gets back.
     */
    public static function match(
        TotpSecret $secret,
        #[\SensitiveParameter] string $code,
        DateTimeImmutable $instant,
        ?int $lastUsedStep,
    ): ?int {
        if (preg_match('/^\d{' . self::DIGITS . '}$/D', $code) !== 1) {
            return null;
        }

        $now = self::timeStep($instant);
        $matched = null;
        for ($step = $now - self::WINDOW; $step <= $now + self::WINDOW; ++$step) {
            // Every step is computed and compared, so the answer takes the same time
            // whichever step matched, if any.
            $matches = hash_equals(self::hotp($secret, $step), $code);
            if ($matches && $matched === null && ($lastUsedStep === null || $step > $lastUsedStep)) {
                $matched = $step;
            }
        }

        return $matched;
    }

    /**
     * The `otpauth://` URI a QR code encodes (Google Authenticator's Key Uri Format).
     * The issuer appears twice — label prefix and parameter — because apps disagree about
     * which one they read.
     */
    public static function provisioningUri(TotpSecret $secret, string $account, string $issuer): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account) . '?' . http_build_query(
            [
                'secret' => $secret->base32(),
                'issuer' => $issuer,
                'algorithm' => self::ALGORITHM,
                'digits' => self::DIGITS,
                'period' => self::PERIOD,
            ],
            '',
            '&',
            PHP_QUERY_RFC3986,
        );
    }
}
