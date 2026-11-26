<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Oidc;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Oidc\Logout\EndSession;
use Clavia\Application\Oidc\Logout\EndSessionRequest;
use Clavia\Application\Oidc\Logout\SignOutConfirmationNeeded;
use Fig\Http\Message\RequestMethodInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /oidc/logout` — the end-session endpoint (OpenID Connect RP-Initiated
 * Logout 1.0 §2: both methods; a POST carries its parameters as a form).
 *
 * An application sends the browser here with a top-level navigation, the only
 * cross-site request the `SameSite=Lax` session cookie rides on. The decision is
 * {@see EndSession}'s; this handler sends the browser on (`303`, the session cookie
 * expired when a session ended) or shows the confirmation, whose form posts back here
 * with `confirmed`. That POST comes from this origin, so the session cookie is with
 * it; a forged one from another site arrives without it and ends nothing.
 *
 * A parameter sent twice counts as not sent.
 */
final readonly class EndSessionHandler implements RequestHandlerInterface
{
    public const string CONFIRMATION_TEMPLATE = 'auth::logout-confirm';

    public function __construct(
        private EndSession $endSession,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $parameters = $request->getMethod() === RequestMethodInterface::METHOD_POST
            ? RequestParameterReader::form($request)
            : RequestParameterReader::query($request);
        $one = static fn (string $name): ?string => self::once($parameters, $name);

        $outcome = ($this->endSession)(new EndSessionRequest(
            $one('id_token_hint'),
            $one('client_id'),
            $one('post_logout_redirect_uri'),
            $one('state'),
            $request->getMethod() === RequestMethodInterface::METHOD_POST && $one('confirmed') === 'yes',
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome instanceof SignOutConfirmationNeeded) {
            return $this->responder->page($request, self::confirmation($outcome));
        }

        return $this->responder->redirect(
            $outcome->location,
            $outcome->sessionEnded ? [$this->cookies->expireSession()] : [],
        );
    }

    public static function confirmation(SignOutConfirmationNeeded $outcome): HtmlPage
    {
        $origin = $outcome->destinationOrigin();

        return new HtmlPage(
            template: self::CONFIRMATION_TEMPLATE,
            title: 'Sign out',
            heading: 'Sign out?',
            returnTo: '/auth/login',
            variables: [
                'clientName' => $outcome->clientName,
                // Carried back exactly as checked; nothing unchecked is printed.
                'fields' => array_filter([
                    'client_id' => $outcome->clientId,
                    'post_logout_redirect_uri' => $outcome->postLogoutRedirectUri,
                    'state' => $outcome->state,
                ], static fn (?string $value): bool => $value !== null),
            ],
            // Chromium checks form-action along the redirect that follows the POST.
            formOrigins: $origin === null ? [] : [$origin],
        );
    }

    private static function once(RequestParameters $parameters, string $name): ?string
    {
        return $parameters->isRepeated($name) ? null : $parameters->get($name);
    }
}
