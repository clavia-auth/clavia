<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use DOMDocument;
use DOMElement;
use LogicException;

/**
 * A QR code as inline SVG markup, for the enrollment page.
 *
 * The auth origin runs no script, so the code is drawn here and embedded as markup —
 * which the page's `default-src 'none'` allows: inline SVG is neither a script nor a
 * style. The library's output is rewritten through the DOM rather than with patterns:
 * the XML declaration, the background rectangle and every colour go, the image draws in
 * `currentColor` so it follows the page's light or dark theme, and it is labelled for
 * assistive technology. No `style` attribute is ever produced.
 */
final class QrCodeSvg
{
    private const int SIZE = 240;

    private const int MARGIN = 2;

    private function __construct()
    {
    }

    public static function of(#[\SensitiveParameter] string $data): string
    {
        $svg = new Writer(new ImageRenderer(new RendererStyle(self::SIZE, self::MARGIN), new SvgImageBackEnd()))
            ->writeString($data);

        $document = new DOMDocument();
        if ($svg === '' || ! $document->loadXML($svg, LIBXML_NONET)) {
            throw new LogicException('The QR code library produced SVG that does not parse.');
        }
        $root = $document->documentElement ?? throw new LogicException('The QR code SVG has no root.');

        // Copied out first: a live node list skips entries when one is removed under it.
        /** @var list<DOMElement> $backgrounds */
        $backgrounds = iterator_to_array($root->getElementsByTagName('rect'), false);
        foreach ($backgrounds as $background) {
            $background->parentNode?->removeChild($background);
        }
        /** @var list<DOMElement> $elements */
        $elements = iterator_to_array($root->getElementsByTagName('*'), false);
        foreach ($elements as $element) {
            $element->removeAttribute('fill');
            $element->removeAttribute('style');
        }
        $root->setAttribute('fill', 'currentColor');
        $root->setAttribute('role', 'img');
        $root->setAttribute('aria-label', 'QR code to scan with an authenticator app');

        $markup = $document->saveXML($root);

        return $markup === false ? throw new LogicException('The QR code SVG cannot be serialised.') : $markup;
    }
}
