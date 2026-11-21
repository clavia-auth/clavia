<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\External\BeginExternalSignIn;
use Clavia\Application\Authentication\External\ExternalSignInUnavailable;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/social/{provider}` — send the browser out to an external provider.
 *
 * A GET, because it is a navigation from a link on the login page, and it changes
 * nothing but a short-lived pending entry: there is no form to protect. `state` in the
 * query is the login page's handle, carried so the sign-in comes back to the same
 * authorization request. An unknown provider and an unconfigured one are the same 404:
 * a deployment without GitHub does not advertise a half-built integration. A connection
 * the application does not enable is refused on the login page (400): refused, not
 * merely hidden.
 */
final readonly class ExternalSignInHandler implements RequestHandlerInterface
{
    public function __construct(
        private BeginExternalSignIn $begin,
        private DescribeLoginPage $describe,
        private AuthPageResponder $responder,
        private ErrorResponder $errors,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $loginState = RequestParameterReader::query($request)->get('state');
        $started = ($this->begin)(self::provider($request), $loginState);
        if ($started === null) {
            return $this->errors->notFound($request);
        }
        if ($started instanceof ExternalSignInUnavailable) {
            return $this->responder->page($request, LoginPages::form(
                $loginState,
                $this->describe->formOrigins($loginState),
                $this->describe->methods($loginState),
                null,
                ExternalSignInMessages::notAvailable($started->providerLabel),
                400,
            ));
        }

        return $this->responder->redirect(
            $started->authorizationUrl,
            [$this->cookies->externalSignIn($started->handle)],
        );
    }

    /** The provider the route matched; anything that is not a string matches no provider. */
    public static function provider(ServerRequestInterface $request): string
    {
        /** @var mixed $provider */
        $provider = $request->getAttribute('provider');

        return is_string($provider) ? $provider : '';
    }
}
