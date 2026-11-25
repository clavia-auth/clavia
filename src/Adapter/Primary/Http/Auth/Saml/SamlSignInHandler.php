<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth\Saml;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInMessages;
use Clavia\Adapter\Primary\Http\Auth\LoginPages;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\External\ExternalSignInUnavailable;
use Clavia\Application\Authentication\External\Saml\BeginSamlSignIn;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/saml/{connection}`: send the browser to the identity provider (HTTP-Redirect binding), the
 * pending sign-in's handle in `RelayState` and in the `clavia_external_state` cookie.
 */
final readonly class SamlSignInHandler implements RequestHandlerInterface
{
    public function __construct(
        private BeginSamlSignIn $begin,
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
        $started = ($this->begin)(self::connection($request), $loginState);
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
                StatusCodeInterface::STATUS_BAD_REQUEST,
            ));
        }

        return $this->responder->redirect(
            $started->authorizationUrl,
            [$this->cookies->externalSignIn($started->handle)],
        );
    }

    /** The connection the route matched. */
    public static function connection(ServerRequestInterface $request): string
    {
        /** @var mixed $connection */
        $connection = $request->getAttribute('connection');

        return is_string($connection) ? $connection : '';
    }
}
