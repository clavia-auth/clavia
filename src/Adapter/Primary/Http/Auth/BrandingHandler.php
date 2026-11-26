<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Application\Authentication\Branding\DescribeBranding;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/branding/{client_id}/logo` and `…/style.css` (#25): the two files an application's sign-in
 * pages name, served from this origin so the pages' policy holds as it is (`img-src 'self'`, no inline
 * style). Public, like a client id: they show what any sign-in page of the application shows.
 *
 * The logo goes out with the media type its content was recognised as, `nosniff`, and a policy of its own
 * that allows nothing, so it is only ever an image. The stylesheet is three custom properties built from
 * a colour already checked to be six hexadecimal digits. Anything unknown is a bare `404`.
 */
final readonly class BrandingHandler implements RequestHandlerInterface
{
    private const array HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'Content-Security-Policy' => "default-src 'none'; sandbox",
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ];

    public function __construct(private DescribeBranding $describe)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $raw */
        $raw = $request->getAttribute('client_id');
        try {
            // The page wrote it percent-encoded (BrandingChoice::view()); the router hands it over as sent.
            $clientId = ClientId::fromString(is_string($raw) ? rawurldecode($raw) : '');
        } catch (InvalidValue) {
            return self::notFound();
        }

        return $request->getAttribute('file') === 'logo' ? $this->logo($clientId) : $this->style($clientId);
    }

    private function logo(ClientId $clientId): ResponseInterface
    {
        $logo = $this->describe->logo($clientId);
        if ($logo === null) {
            return self::notFound();
        }
        $response = (new Response())->withHeader('Content-Type', $logo->mediaType);
        $response->getBody()->write($logo->content);
        foreach (self::HEADERS as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    private function style(ClientId $clientId): ResponseInterface
    {
        $color = ($this->describe)($clientId)?->accentColor;
        if ($color === null) {
            return self::notFound();
        }
        $css = sprintf(
            ":root {\n  --accent: %1\$s;\n  --accent-hover: color-mix(in srgb, %1\$s 85%%, #000);\n"
            . "  --accent-text: %2\$s;\n}\n",
            $color->hex,
            $color->textColor(),
        );

        return new TextResponse($css, StatusCodeInterface::STATUS_OK, self::HEADERS + [
            'Content-Type' => 'text/css; charset=utf-8',
        ]);
    }

    private static function notFound(): ResponseInterface
    {
        return new EmptyResponse(StatusCodeInterface::STATUS_NOT_FOUND, self::HEADERS);
    }
}
