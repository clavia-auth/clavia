<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Relationships;

use RuntimeException;

/**
 * A relationship the Authorization API will not write or read (docs/design/fine-grained-authorization.md
 * §5.3), pointing at what is at fault: a JSON pointer into the request's body, or a query parameter.
 * The message never repeats a value the caller sent.
 */
final class RelationshipRefused extends RuntimeException
{
    private function __construct(
        string $message,
        /** A JSON pointer into the body (`/writes/2/resource/type`), or '' when the fault is elsewhere. */
        public readonly string $pointer = '',
        /** The query parameter at fault, or '' when the fault is in the body. */
        public readonly string $parameter = '',
    ) {
        parent::__construct($message);
    }

    /** One of Clavia's types: `user`, `client`, `role`, `group` are written by Clavia alone. */
    public static function reservedType(string $pointer = '', string $parameter = ''): self
    {
        return new self('This type is Clavia\'s: its relationships are written by Clavia alone.', $pointer, $parameter);
    }

    /** A type the API's model does not declare: another API's, or none. */
    public static function unknownType(string $pointer = '', string $parameter = ''): self
    {
        return new self('The API\'s authorization model declares no such type.', $pointer, $parameter);
    }

    /** A person or an application Clavia does not know. */
    public static function unknownSubject(string $pointer): self
    {
        return new self('Clavia knows no such subject.', $pointer);
    }

    public static function tooMany(int $max): self
    {
        return new self(sprintf('At most %d relationships are written and deleted at once.', $max), '/writes');
    }

    /** The decision engine refused the write, with its own error code. */
    public static function byEngine(string $code): self
    {
        return new self(sprintf('The decision engine refused the change (%s): nothing was written.', $code));
    }

    public static function pageToken(): self
    {
        return new self('The page token is not one this API handed out.', parameter: 'page_token');
    }
}
