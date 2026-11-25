<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth\Saml;

use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Shared\ErrorPage;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\External\Saml\ReceiveSamlResponse;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/saml/{connection}/acs`, the assertion consumer service (Bindings §3.5, HTTP-POST). **The one
 * `/auth/*` POST without a CSRF token**: it comes from the identity provider's page, and it changes nothing
 * but a short-lived handle. It parks the response and answers `303` to the GET where the browser's cookies
 * come back (docs/design/saml-connections.md §2, "The browser binding"). Nothing is read or decided here.
 */
final readonly class SamlAcsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReceiveSamlResponse $receive,
        private AuthPageResponder $responder,
        private ErrorResponder $errors,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $form = RequestParameterReader::form($request);
        $connection = SamlSignInHandler::connection($request);
        $handle = ($this->receive)(
            $connection,
            $form->isRepeated('SAMLResponse') ? null : $form->get('SAMLResponse'),
            $form->isRepeated('RelayState') ? null : $form->get('RelayState'),
        );
        if ($handle === null) {
            return $this->errors->respond(
                $request,
                StatusCodeInterface::STATUS_BAD_REQUEST,
                new ErrorPage(
                    'This sign-in could not be read',
                    'Your identity provider sent something that is not a sign-in response.',
                    'Go back to the application and sign in again.',
                ),
                ['error' => 'invalid_request'],
                ['Cache-Control' => 'no-store'],
            );
        }

        return $this->responder->redirect(
            '/auth/saml/' . rawurlencode($connection) . '/complete?'
            . http_build_query(['h' => $handle], '', '&', PHP_QUERY_RFC3986),
        );
    }
}
