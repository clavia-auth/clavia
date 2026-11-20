<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Http\OAuth2;

use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\OAuth2Error;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Encodes what the OAuth2 use cases decided as HTTP: the JSON bodies of RFC 6749 §5,
 * the redirects of §4.1.2, and the headers each must carry.
 *
 * Nothing here decides anything about the protocol; it only knows how a decision
 * travels.
 */
final readonly class OAuth2Responder
{
    /**
     * RFC 6749 §5.1: a response carrying tokens or credentials-related errors must not
     * be stored by any cache.
     */
    private const array NO_STORE = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];

    /**
     * @param string $issuer The issuer identifier: the `iss` of authorization responses and the realm of
     *                       authentication challenges.
     */
    public function __construct(
        private ResponseFactoryInterface $responses,
        private string $issuer,
    ) {
    }

    /**
     * A successful JSON response (RFC 6749 §5.1).
     *
     * @param array<string, mixed> $payload
     */
    public function success(array $payload): ResponseInterface
    {
        return new JsonResponse($payload, 200, self::NO_STORE);
    }

    /**
     * An error of the token endpoint, answered to the client (RFC 6749 §5.2).
     *
     * A failed client authentication is a 401 carrying `WWW-Authenticate`: RFC 9110
     * §11.6.1 requires the header on every 401, and RFC 6749 §5.2 specifically when the
     * client used the `Authorization` header. Everything else is a 400.
     */
    public function tokenError(OAuth2Error $error): ResponseInterface
    {
        if ($error->error === ErrorCode::InvalidClient) {
            return new JsonResponse(
                self::document($error),
                401,
                self::NO_STORE + ['WWW-Authenticate' => sprintf('Basic realm="%s"', $this->issuer)],
            );
        }

        return new JsonResponse(self::document($error), 400, self::NO_STORE);
    }

    /**
     * An error of the authorization endpoint that must not be redirected — the client or
     * its redirect URI could not be established — so it is shown where it happened
     * (RFC 6749 §4.1.2.1).
     *
     * Always a 400, and never a challenge: this endpoint is visited by a person's
     * browser, where `WWW-Authenticate: Basic` would raise a password prompt for a
     * client secret nobody at the keyboard has.
     */
    public function authorizationError(OAuth2Error $error): ResponseInterface
    {
        return new JsonResponse(self::document($error), 400, self::NO_STORE);
    }

    /**
     * An authorization response: a redirect to the client's validated redirect URI with
     * the response parameters in its query (RFC 6749 §4.1.2 and §4.1.2.1).
     *
     * Every such response — success or error — names its issuer (RFC 9207 §2), so a
     * client that talks to more than one authorization server can tell which one
     * answered (the "mix-up" attack). And none may come out of a cache: it carries a
     * single-use code and depends on who is signed in.
     *
     * @param string                     $redirectUri A redirect URI already validated against the client's
     *                                                registration. Never anything else.
     * @param array<string, string|null> $parameters  Null values are left out.
     */
    public function redirectToClient(string $redirectUri, array $parameters): ResponseInterface
    {
        $parameters = array_filter(
            // The issuer is this server's to state: it replaces whatever a caller passed.
            [...$parameters, 'iss' => $this->issuer],
            static fn (?string $value): bool => $value !== null,
        );
        $query = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        // Appended, never substituted: whatever query the registered URI already has is kept as it is.
        $location = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . $query;

        return $this->responses->createResponse(302)
            ->withHeader('Location', $location)
            ->withHeader('Cache-Control', 'no-store');
    }

    /**
     * Send the browser to a page of this server (the login page), by path.
     *
     * 303, so the browser follows with a GET whatever method brought it here. Not
     * cacheable either: whether it happens depends on whether a session was presented.
     */
    public function redirectWithinServer(string $pathAndQuery): ResponseInterface
    {
        return $this->responses->createResponse(303)
            ->withHeader('Location', $pathAndQuery)
            ->withHeader('Cache-Control', 'no-store');
    }

    /**
     * The error document of RFC 6749 §5.2.
     *
     * @return array{error: string, error_description: string}
     */
    private static function document(OAuth2Error $error): array
    {
        return ['error' => $error->error->value, 'error_description' => $error->description];
    }
}
