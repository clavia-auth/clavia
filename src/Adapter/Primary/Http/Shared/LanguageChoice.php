<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The language a page is shown in (docs/design/translated-sign-in-pages.md §5.1): what the browser asks
 * for in `Accept-Language` (RFC 9110 §12.5.4), by preference, matched against the offered languages
 * (RFC 4647 §3.4 lookup); otherwise the default. Only ever an offered language.
 */
final readonly class LanguageChoice
{
    /** A browser's list is short; a longer one is read no further than this. */
    private const int MAX_RANGES = 10;

    public function __construct(private Languages $languages)
    {
    }

    public function __invoke(ServerRequestInterface $request): Language
    {
        foreach (self::ranges($request->getHeaderLine('Accept-Language')) as $range) {
            $language = $this->languages->lookup($range);
            if ($language !== null) {
                return $language;
            }
        }

        return $this->languages->default;
    }

    /**
     * The ranges of an `Accept-Language` value, most wanted first, ties in the order sent; `q=0` ("not
     * this") and malformed members left out.
     *
     * @return list<string>
     */
    public static function ranges(string $header): array
    {
        $weighted = [];
        foreach (array_slice(explode(',', $header), 0, self::MAX_RANGES) as $position => $member) {
            $parts = array_map('trim', explode(';', $member));
            $range = array_shift($parts);
            if ($range === '') {
                continue;
            }
            $weight = 1.0;
            foreach ($parts as $parameter) {
                if (preg_match('/^q\s*=\s*(0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)$/Di', $parameter, $q) !== 1) {
                    continue 2;
                }
                $weight = (float) $q[1];
            }
            if ($weight > 0.0) {
                $weighted[] = [$range, $weight, $position];
            }
        }
        usort($weighted, static fn (array $a, array $b): int => [$b[1], $a[2]] <=> [$a[1], $b[2]]);

        return array_map(static fn (array $entry): string => $entry[0], $weighted);
    }
}
