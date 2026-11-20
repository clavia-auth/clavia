<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

/**
 * What an error page tells a person: what happened, and what they can do about it.
 *
 * Written for whoever is at the keyboard, who is usually not the one who can fix the
 * cause. No text here ever comes from the request.
 */
final readonly class ErrorPage
{
    /**
     * @param string      $title   The heading: what happened, in a few words.
     * @param string      $message What happened, in a sentence.
     * @param string      $advice  What to do now.
     * @param string|null $code    A reference to quote to whoever can help: an OAuth2 error code,
     *                             a log reference. Null when there is nothing worth quoting.
     */
    public function __construct(
        public string $title,
        public string $message,
        public string $advice,
        public ?string $code = null,
    ) {
    }

    public static function notFound(): self
    {
        return new self(
            'Page not found',
            'There is nothing at this address.',
            'Check the link, or go back to the application that sent you here.',
        );
    }

    public static function methodNotAllowed(): self
    {
        return new self(
            'This page cannot be opened this way',
            'This address exists, but not for the kind of request your browser made.',
            'Go back to the application that sent you here and start again from there.',
        );
    }

    /**
     * @param string $reference The identifier the failure was logged under.
     */
    public static function internalError(string $reference): self
    {
        return new self(
            'Something went wrong',
            'The server could not complete this request. Nothing you did caused it.',
            'Try again in a moment. If it keeps happening, contact whoever runs this service '
                . 'and quote the reference below.',
            $reference,
        );
    }

    /**
     * An authorization request that cannot be sent back to the application, because the
     * application or its return address could not be trusted (RFC 6749 §4.1.2.1).
     *
     * @param string $description The server's own description of the error; never request text.
     * @param string $code        The OAuth2 error code.
     */
    public static function authorizationRefused(string $description, string $code): self
    {
        return new self(
            'This sign-in cannot continue',
            $description,
            'The application that sent you here made a request this server cannot accept. '
                . 'Close this page and go back to the application; if it keeps happening, tell whoever runs it.',
            $code,
        );
    }

    /**
     * The page, rendered in the shared layout. No colour-scheme toggle: posting it would
     * bring the browser back to the request that just failed.
     */
    public function toHtmlPage(int $status): HtmlPage
    {
        return new HtmlPage(
            template: 'error::page',
            title: $this->title,
            heading: $this->title,
            variables: ['message' => $this->message, 'advice' => $this->advice, 'code' => $this->code],
            status: $status,
        );
    }
}
