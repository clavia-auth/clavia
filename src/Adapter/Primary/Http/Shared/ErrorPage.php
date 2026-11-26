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
     * @param Message|string $title   The heading: what happened, in a few words.
     * @param Message|string $message What happened, in a sentence.
     * @param Message|string $advice  What to do now.
     * @param string|null    $code    A reference to quote to whoever can help: an OAuth2 error code,
     *                                a log reference. Null when there is nothing worth quoting.
     * @param string|null    $detail  The server's own technical description, for an application's
     *                                developer: English, as every OAuth `error_description` is.
     */
    public function __construct(
        public Message|string $title,
        public Message|string $message,
        public Message|string $advice,
        public ?string $code = null,
        public ?string $detail = null,
    ) {
    }

    public static function notFound(): self
    {
        return new self(
            Message::of('error.not_found.title'),
            Message::of('error.not_found.message'),
            Message::of('error.not_found.advice'),
        );
    }

    public static function methodNotAllowed(): self
    {
        return new self(
            Message::of('error.method_not_allowed.title'),
            Message::of('error.method_not_allowed.message'),
            Message::of('error.method_not_allowed.advice'),
        );
    }

    /**
     * @param string $reference The identifier the failure was logged under.
     */
    public static function internalError(string $reference): self
    {
        return new self(
            Message::of('error.internal.title'),
            Message::of('error.internal.message'),
            Message::of('error.internal.advice'),
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
            Message::of('error.authorization_refused.title'),
            Message::of('error.authorization_refused.message'),
            Message::of('error.authorization_refused.advice'),
            $code,
            $description,
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
            variables: [
                'message' => $this->message,
                'advice' => $this->advice,
                'code' => $this->code,
                'detail' => $this->detail,
            ],
            status: $status,
        );
    }
}
