<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Application\Authentication\Branding\Branding;
use Clavia\Application\Authentication\Branding\DescribeBranding;
use Clavia\Application\Authentication\HeldRequests;
use Clavia\Application\Authentication\ResolveEndUser;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The look of a page (#25): the branding of the application whose authorization request the page serves,
 * found as its language is ({@see HeldRequests}: the page's `state`, or the second-factor cookie). None
 * for a page that serves no request, or an application that is gone: this server's own look.
 *
 * A pending consent is bound to the person it was put to: its application shows to them alone, so a handle
 * that is someone else's gives the same plain "expired" page as one that does not exist.
 *
 * A page names the application's files on this origin only, versioned by their content, so the pages'
 * policy holds as it is: no inline style, no image from anywhere else.
 */
final readonly class BrandingChoice
{
    public const string PATH = '/auth/branding/';

    public function __construct(
        private HeldRequests $held,
        private DescribeBranding $describe,
        private ResolveEndUser $resolveEndUser,
        private AuthCookies $cookies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request): ?Branding
    {
        $held = ($this->held)(
            RequestParameterReader::queryAndForm($request)->get('state'),
            RequestCookies::first($request, AuthCookies::MFA_CHALLENGE),
        );
        if ($held->clientId === null) {
            return null;
        }
        if ($held->askedOf !== null) {
            $viewer = ($this->resolveEndUser)(RequestCookies::first($request, $this->cookies->sessionCookieName));
            if ($viewer === null || ! $viewer->userId->equals($held->askedOf)) {
                return null;
            }
        }

        return ($this->describe)($held->clientId);
    }

    /**
     * What the layout prints: the application's name, and its logo's and stylesheet's addresses, each
     * null when it has none.
     *
     * @return array{name: string, logo: string|null, style: string|null}
     */
    public static function view(Branding $branding): array
    {
        $base = self::PATH . rawurlencode($branding->clientId->value);

        return [
            'name' => $branding->name,
            'logo' => $branding->logoVersion === null ? null : $base . '/logo?v=' . $branding->logoVersion,
            'style' => $branding->accentColor === null
                ? null
                : $base . '/style.css?v=' . substr($branding->accentColor->hex, 1),
        ];
    }
}
