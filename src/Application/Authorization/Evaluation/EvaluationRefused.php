<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

use RuntimeException;

/**
 * A question that cannot be asked (AuthZEN 1.0 §10.1.1: `400`): a subject that is neither a person
 * nor an application, a type or a relation the API's model does not declare, or a `context.clavia`,
 * which is Clavia's to write. In a batch it is that question's denial instead (§7.2.1). The message
 * never repeats a value the caller sent.
 */
final class EvaluationRefused extends RuntimeException
{
    private function __construct(string $message, public readonly ?DenialReason $reason = null)
    {
        parent::__construct($message);
    }

    public static function subjectKind(): self
    {
        return new self('A subject is a person (`user`) or an application (`client`).', DenialReason::UnknownType);
    }

    public static function unknownType(): self
    {
        return new self('The API\'s authorization model declares no such type.', DenialReason::UnknownType);
    }

    public static function unknownRelation(): self
    {
        return new self(
            'The API\'s authorization model gives the resource\'s type no such relation.',
            DenialReason::UnknownType,
        );
    }

    public static function claviaContext(): self
    {
        return new self('`context.clavia` is Clavia\'s to write: what it knows of the subject.');
    }

    /** A batch item with no subject, action or resource, given or defaulted (AuthZEN 1.0 §7.1). */
    public static function incomplete(): self
    {
        return new self('Each evaluation has a subject, an action and a resource, its own or the request\'s.');
    }

    /** A search's page token that is not one this search handed out, or the search changed since (AuthZEN §8.2). */
    public static function pageToken(): self
    {
        return new self('The page token is not one this search handed out, or the search changed since.');
    }

    public static function malformed(): self
    {
        return new self('An identifier or an action is not one OpenFGA\'s notation takes.');
    }
}
